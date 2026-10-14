function report = validate_recovery(manifestPath, reportPath)
%validate_recovery - Analyze and reencode recovered P-code candidates
%   REPORT = validate_recovery(manifestPath) checks candidate syntax and
%   regenerates legacy P-code in a temporary directory. It writes
%   matlab_validation.json in the manifest output directory.
%
%   REPORT = validate_recovery(manifestPath,reportPath) also specifies the
%   JSON report location. Candidate functions and scripts are never run.
%
%   See also checkcode, pcode, jsondecode

if ~usejava('jvm')
    error('Recovery:NoJVM', 'A JVM is required for path and SHA-256 checks.');
end
manifestPath = absolutePath(manifestPath, 'ManifestPath');
manifestBytes = readBytes(manifestPath);
manifest = jsondecode(native2unicode(manifestBytes.', 'UTF-8'));
if ~isstruct(manifest) || ~isfield(manifest, 'schema_version') || ...
        manifest.schema_version ~= 1 || ...
        ~isfield(manifest, 'tool') || ...
        ~strcmp(manifest.tool, 'recover-matlab-pcode')
    error('Recovery:InvalidManifest', 'Unsupported recovery manifest.');
end
required = {'input_path', 'layout_root', 'output_dir', 'files'};
for k = 1:numel(required)
    if ~isfield(manifest, required{k})
        error('Recovery:InvalidManifest', 'Missing field %s.', required{k});
    end
end
inputRoot = absolutePath(manifest.input_path, 'input_path');
layoutRoot = absolutePath(manifest.layout_root, 'layout_root');
outputRoot = absolutePath(manifest.output_dir, 'output_dir');
if ~insidePath(manifestPath, outputRoot)
    error('Recovery:ManifestScope', 'The manifest is outside its output directory.');
end
if (isfolder(inputRoot) && (insidePath(outputRoot, inputRoot) || ...
        insidePath(inputRoot, outputRoot) || samePath(inputRoot, outputRoot))) || ...
        (~isfolder(inputRoot) && (samePath(inputRoot, outputRoot) || ...
        insidePath(inputRoot, outputRoot)))
    error('Recovery:OutputScope', 'Input and output directory scopes overlap.');
end
if nargin < 2 || isempty(reportPath)
    reportPath = fullfile(outputRoot, 'matlab_validation.json');
end
reportPath = absolutePath(reportPath, 'reportPath');
files = manifest.files;
if ~isempty(files) && ~isstruct(files)
    error('Recovery:InvalidManifest', 'files must be an array of objects.');
end
protectedPaths = {manifestPath};
relativePaths = cell(numel(files), 1);
sourcePaths = cell(numel(files), 1);
inputPaths = cell(numel(files), 1);
for k = 1:numel(files)
    item = files(k);
    relative = relativePath(item.relative_path);
    relativePaths{k} = relative;
    inputPaths{k} = absolutePath(item.input_path, 'input_path');
    expectedInput = absolutePath(fullfile(layoutRoot, strrep(relative, '/', filesep)), 'input_path');
    if ~samePath(inputPaths{k}, expectedInput) || ...
            ~insidePath(inputPaths{k}, layoutRoot) || ...
            ~(insidePath(inputPaths{k}, inputRoot) || samePath(inputPaths{k}, inputRoot))
        error('Recovery:InputScope', 'Input is outside the manifest scope: %s', relative);
    end
    protectedPaths{end + 1} = inputPaths{k}; %#ok<AGROW>
    sourcePaths{k} = '';
    if ~isempty(item.source_path)
        sourcePaths{k} = absolutePath(item.source_path, 'source_path');
        expectedSource = absolutePath(fullfile(outputRoot, 'sources', ...
            strrep([relative(1:end - 2), '.m'], '/', filesep)), 'source_path');
        if ~samePath(sourcePaths{k}, expectedSource) || ...
                ~insidePath(sourcePaths{k}, outputRoot)
            error('Recovery:SourceScope', 'Source is outside its manifest scope: %s', relative);
        end
        protectedPaths{end + 1} = sourcePaths{k}; %#ok<AGROW>
    end
end
if ispc
    duplicateKeys = lower(string(relativePaths));
else
    duplicateKeys = string(relativePaths);
end
if numel(unique(duplicateKeys)) ~= numel(files)
    error('Recovery:DuplicateRecord', 'Manifest relative paths are not unique.');
end
if any(cellfun(@(p) samePath(reportPath, p), protectedPaths))
    error('Recovery:UnsafeReportPath', 'Report would overwrite a protected file.');
end
[~, ~, reportExtension] = fileparts(reportPath);
if ~strcmpi(reportExtension, '.json')
    error('Recovery:UnsafeReportPath', 'Report output must have a .json extension.');
end
if insidePath(reportPath, inputRoot) || ...
        (~isfolder(inputRoot) && samePath(reportPath, inputRoot))
    error('Recovery:UnsafeReportPath', 'Report output overlaps the input scope.');
end
if isfile(reportPath)
    previous = jsondecode(native2unicode(readBytes(reportPath).', 'UTF-8'));
    if ~isstruct(previous) || ~isfield(previous, 'Tool') || ...
            ~strcmp(previous.Tool, 'recover-matlab-pcode') || ...
            ~isfield(previous, 'Kind') || ...
            ~strcmp(previous.Kind, 'matlab_validation') || ...
            ~isfield(previous, 'ManifestPath') || ...
            ~samePath(absolutePath(previous.ManifestPath, 'ManifestPath'), manifestPath)
        error('Recovery:UnsafeReportPath', 'Refusing to overwrite an unrelated file.');
    end
end
verificationRoot = absolutePath(tempname, 'VerificationRoot');
if (isfolder(inputRoot) && insidePath(verificationRoot, inputRoot)) || ...
        insidePath(verificationRoot, outputRoot) || ...
        insidePath(inputRoot, verificationRoot) || ...
        insidePath(outputRoot, verificationRoot)
    error('Recovery:TemporaryScope', 'Temporary verification scope overlaps recovery data.');
end
mkdir(verificationRoot);
template = struct('RelativePath', '', 'InputPath', '', 'SourcePath', '', ...
    'RegeneratedPath', '', 'Status', '', 'AnalyzerMessages', [], ...
    'SourceSHA256', '', 'RegeneratedSHA256', '', ...
    'ErrorIdentifier', '', 'ErrorMessage', '');
records = repmat(template, numel(files), 1);
decodedStatuses = {'decoded_unverified', 'verified_payload_identical', ...
    'validation_failed', 'source_changed', 'input_changed', 'payload_mismatch'};
for k = 1:numel(files)
    item = files(k);
    records(k).RelativePath = relativePaths{k};
    records(k).InputPath = inputPaths{k};
    records(k).SourcePath = sourcePaths{k};
    decodeStatus = item.status;
    if isfield(item, 'decode_status')
        decodeStatus = item.decode_status;
    end
    if ~any(strcmp(decodeStatus, decodedStatuses)) || isempty(sourcePaths{k})
        records(k).Status = 'skipped_not_decoded';
        continue
    end
    candidate = fullfile(verificationRoot, ...
        strrep([relativePaths{k}(1:end - 2), '.m'], '/', filesep));
    regenerated = fullfile(verificationRoot, ...
        strrep([relativePaths{k}(1:end - 2), '.p'], '/', filesep));
    records(k).RegeneratedPath = regenerated;
    try
        records(k).SourceSHA256 = hashBytes(readBytes(sourcePaths{k}));
        if ~isfolder(fileparts(candidate))
            mkdir(fileparts(candidate));
        end
        [copied, copyMessage] = copyfile(sourcePaths{k}, candidate);
        if ~copied
            error('Recovery:CopyFailed', '%s', copyMessage);
        end
        if ~strcmp(hashBytes(readBytes(candidate)), records(k).SourceSHA256)
            error('Recovery:SourceChanged', 'Source changed while copying.');
        end
        records(k).AnalyzerMessages = checkcode(candidate, '-id');
        pcode(candidate, '-R2007b', '-inplace');
        if ~isfile(regenerated)
            error('Recovery:MissingRegenerated', 'MATLAB did not create the expected P-code.');
        end
        if ~strcmp(hashBytes(readBytes(sourcePaths{k})), records(k).SourceSHA256)
            error('Recovery:SourceChanged', 'Source changed during validation.');
        end
        records(k).RegeneratedSHA256 = hashBytes(readBytes(regenerated));
        records(k).Status = 'reencoded';
    catch validationError
        records(k).Status = 'failed';
        records(k).ErrorIdentifier = validationError.identifier;
        records(k).ErrorMessage = validationError.message;
    end
end
if ~strcmp(hashBytes(readBytes(manifestPath)), hashBytes(manifestBytes))
    error('Recovery:ManifestChanged', 'Manifest changed during MATLAB validation.');
end
report = struct('SchemaVersion', 1, 'Tool', 'recover-matlab-pcode', ...
    'Kind', 'matlab_validation', 'ManifestPath', manifestPath, ...
    'ManifestSHA256', hashBytes(manifestBytes), ...
    'VerificationRoot', verificationRoot, 'MATLABVersion', version, ...
    'Records', records);
reportDirectory = fileparts(reportPath);
if ~isfolder(reportDirectory)
    mkdir(reportDirectory);
end
jsonBytes = unicode2native(jsonencode(report), 'UTF-8');
handle = fopen(reportPath, 'wb');
if handle == -1
    error('Recovery:CannotWriteReport', 'Cannot write report: %s', reportPath);
end
cleanup = onCleanup(@() fclose(handle));
count = fwrite(handle, jsonBytes, 'uint8');
if count ~= numel(jsonBytes)
    error('Recovery:CannotWriteReport', 'Incomplete report write.');
end
clear cleanup
fprintf('MATLAB validation: %d records, %d reencoded, %d failed.\n', ...
    numel(records), nnz(strcmp({records.Status}, 'reencoded')), ...
    nnz(strcmp({records.Status}, 'failed')));
fprintf('Report: %s\n', reportPath);
end

function value = absolutePath(value, label)
if ~(ischar(value) || (isstring(value) && isscalar(value))) || isempty(value)
    error('Recovery:InvalidPath', '%s must be a nonempty absolute path.', label);
end
value = char(value);
file = javaObject('java.io.File', value);
if ~file.isAbsolute()
    error('Recovery:InvalidPath', '%s must be an absolute path.', label);
end
value = char(file.getCanonicalPath());
end

function value = relativePath(value)
if ~(ischar(value) || (isstring(value) && isscalar(value)))
    error('Recovery:InvalidRelativePath', 'Relative path must be text.');
end
value = char(value);
parts = strsplit(value, '/');
if isempty(value) || startsWith(value, '/') || contains(value, '\') || ...
        contains(value, ':') || any(ismember(parts, {'', '.', '..'})) || ...
        numel(value) < 3 || ~strcmpi(value(end - 1:end), '.p')
    error('Recovery:InvalidRelativePath', 'Invalid POSIX P-code relative path.');
end
end

function result = samePath(left, right)
if ispc
    result = strcmpi(left, right);
else
    result = strcmp(left, right);
end
end

function result = insidePath(path, root)
if root(end) ~= filesep
    root = [root, filesep];
end
if ispc
    result = startsWith(lower(path), lower(root));
else
    result = startsWith(path, root);
end
end

function bytes = readBytes(path)
handle = fopen(path, 'rb');
if handle == -1
    error('Recovery:CannotReadFile', 'Cannot read file: %s', path);
end
cleanup = onCleanup(@() fclose(handle));
bytes = fread(handle, Inf, '*uint8');
end

function digest = hashBytes(bytes)
engine = javaMethod('getInstance', 'java.security.MessageDigest', 'SHA-256');
engine.update(typecast(bytes(:), 'int8'));
digest = lower(reshape(dec2hex(typecast(engine.digest(), 'uint8'), 2).', 1, []));
end