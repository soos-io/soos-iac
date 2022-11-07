# SOOS URLS
DEFAULT_BASE_URL = "https://api.soos.io/api/"
URI_START_IAC_ANALYSIS_TEMPLATE = (
    "{soos_base_uri}clients/{soos_client_id}/scan-types/iac/scans"
)
URI_UPLOAD_IAC_RESULTS_TEMPLATE = "{soos_base_uri}clients/{soos_client_id}/projects/{soos_project_id}/branches/{soos_branch_hash}/scan-types/iac/scans/{soos_analysis_id}"

# Request Headers
HEADER_SOOS_API_KEY = "x-soos-apikey"
HEADER_CONTENT_TYPE = "Content-Type"
JSON_HEADER_CONTENT_TYPE = "application/json"
MULTIPART_HEADER_CONTENT_TYPE = "multipart/form-data"

# Integration metadata
DEFAULT_INTEGRATION_NAME = "None"
DEFAULT_INTEGRATION_TYPE = "Script"
DEFAULT_IAC_TOOL = "Trivy"
DEFAULT_IAC_TOOL_VERSION = "latest"

# On failure values
FAIL_THE_BUILD = "fail_the_build"
CONTINUE_ON_FAILURE = "continue_on_failure"

# Trivy Specific values
DEFAULT_SCAN_TYPE = "config"
DEFAULT_SCAN_FORMAT = "json"
DEFAULT_SCAN_OUTPUT = "results.json"
DEFAULT_SCAN_SEVERITY = "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
DEFAULT_COMMAND_TEMPLATE = "trivy --severity {severity} --format {format} --output {output} {scan_type} {target_to_scan}"
REPORT_SCAN_RESULT_FILENAME = "./results.json"

# LOGS
LOG_FORMAT = "%(asctime)s %(message)s"
LOG_DATE_FORMAT = "%m/%d/%Y %I:%M:%S %p %Z"

# MISC
UTF_8 = 'utf-8'
FILE_READ_MODE = "r"