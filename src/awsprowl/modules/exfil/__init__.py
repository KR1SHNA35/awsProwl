"""
Exfiltration Modules - Data Theft & Extraction

These modules extract data from AWS resources and send it to external destinations.
They require explicit authorization and confirmation before running.
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# Register exfil modules
register_module(ModuleMetadata(
    name="s3__exfil_download_objects",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Download objects from S3 buckets (including versioned objects). DESTRUCTIVE - reads sensitive data.",
    required_permissions=["s3:GetObject", "s3:GetObjectVersion", "s3:ListObjectsV2", "s3:ListObjectVersions", "s3:GetBucketLocation"],
    supported_services=["s3"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["exfil", "s3", "data-theft", "objects", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="s3__exfil_bucket_sync",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Sync entire S3 bucket to local/attacker-controlled destination. DESTRUCTIVE - mass data extraction.",
    required_permissions=["s3:ListObjectsV2", "s3:GetObject", "s3:GetBucketLocation", "s3:GetBucketVersioning"],
    supported_services=["s3"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["exfil", "s3", "sync", "mass-extraction", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="s3__exfil_replication",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Configure cross-region/account replication to attacker-controlled bucket for automated exfiltration. DESTRUCTIVE.",
    required_permissions=["s3:PutBucketReplication", "s3:GetBucketReplication", "iam:PassRole", "s3:GetBucketLocation"],
    supported_services=["s3", "iam"],
    mitre_techniques=["T1020", "T1041", "T1530"],
    tags=["exfil", "s3", "replication", "automated", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="s3__exfil_presigned_urls",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Generate presigned URLs for time-limited object access without leaving CloudTrail GetObject events.",
    required_permissions=["s3:GetObject", "s3:ListObjectsV2"],
    supported_services=["s3"],
    mitre_techniques=["T1530", "T1020", "T1114.001"],
    tags=["exfil", "s3", "presigned-url", "stealth"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="s3__exfil_access_points",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Use S3 Access Points with custom policies for restricted data access. DESTRUCTIVE.",
    required_permissions=["s3:CreateAccessPoint", "s3:GetAccessPoint", "s3:GetObject", "s3:ListAccessPoints"],
    supported_services=["s3"],
    mitre_techniques=["T1530", "T1020"],
    tags=["exfil", "s3", "access-point", "restricted", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="s3__exfil_select_query",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Use S3 Select to query and extract specific data from objects (CSV/JSON/Parquet) without full download.",
    required_permissions=["s3:SelectObjectContent", "s3:GetObject", "s3:ListObjectsV2"],
    supported_services=["s3"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["exfil", "s3", "select", "query", "targeted"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="dynamodb__exfil_scan_table",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Scan/query DynamoDB tables for complete data extraction. DESTRUCTIVE - reads all table data.",
    required_permissions=["dynamodb:Scan", "dynamodb:Query", "dynamodb:DescribeTable", "dynamodb:ListTables"],
    supported_services=["dynamodb"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["exfil", "dynamodb", "scan", "data-theft", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="dynamodb__exfil_export_table",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Export DynamoDB table to S3 for bulk exfiltration. DESTRUCTIVE.",
    required_permissions=["dynamodb:ExportTableToPointInTime", "dynamodb:DescribeExport", "dynamodb:ListExports", "s3:PutObject"],
    supported_services=["dynamodb", "s3"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["exfil", "dynamodb", "export", "s3", "bulk", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="dynamodb__exfil_streams",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Enable DynamoDB Streams and read stream records for real-time data exfiltration. DESTRUCTIVE.",
    required_permissions=["dynamodb:DescribeStream", "dynamodb:GetRecords", "dynamodb:GetShardIterator", "dynamodb:ListStreams"],
    supported_services=["dynamodb"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["exfil", "dynamodb", "streams", "real-time", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="rds__exfil_snapshot",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.CRITICAL,
    description="Create and share RDS snapshot to attacker account for database exfiltration. CRITICAL - full DB copy.",
    required_permissions=["rds:CreateDBSnapshot", "rds:DescribeDBSnapshots", "rds:ModifyDBSnapshotAttribute", "rds:DescribeDBInstances"],
    supported_services=["rds"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["exfil", "rds", "snapshot", "database", "cross-account", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="rds__exfil_clone",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.CRITICAL,
    description="Clone RDS instance to attacker-controlled instance for data access. CRITICAL.",
    required_permissions=["rds:RestoreDBInstanceFromDBSnapshot", "rds:CreateDBSnapshot", "rds:DescribeDBInstances", "ec2:DescribeSubnets"],
    supported_services=["rds", "ec2"],
    mitre_techniques=["T1530", "T1020", "T1611"],
    tags=["exfil", "rds", "clone", "database", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="rds__exfil_data_api",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Use RDS Data API to execute SQL queries for targeted data extraction.",
    required_permissions=["rds-data:ExecuteStatement", "rds-data:BatchExecuteStatement", "rds:DescribeDBInstances", "secretsmanager:GetSecretValue"],
    supported_services=["rds-data", "secretsmanager"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["exfil", "rds", "data-api", "sql", "targeted"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="lambda__exfil_env_vars",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Extract environment variables from Lambda functions (secrets, API keys, DB credentials). DESTRUCTIVE.",
    required_permissions=["lambda:GetFunctionConfiguration", "lambda:ListFunctions", "lambda:GetFunction"],
    supported_services=["lambda"],
    mitre_techniques=["T1555.005", "T1530", "T1041"],
    tags=["exfil", "lambda", "env-vars", "secrets", "credentials", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="lambda__exfil_function_code",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Download Lambda function code packages for source code analysis/extraction. DESTRUCTIVE.",
    required_permissions=["lambda:GetFunction", "lambda:ListFunctions", "lambda:GetFunctionCodeSigningConfig"],
    supported_services=["lambda"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["exfil", "lambda", "code", "source-code", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="lambda__exfil_layer_code",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Download Lambda layer code for analysis/extraction.",
    required_permissions=["lambda:GetLayerVersion", "lambda:ListLayerVersions", "lambda:ListLayers"],
    supported_services=["lambda"],
    mitre_techniques=["T1530", "T1020"],
    tags=["exfil", "lambda", "layer", "code"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="ec2__exfil_user_data",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Extract EC2 instance user data (often contains secrets, scripts, configs).",
    required_permissions=["ec2:DescribeInstanceAttribute", "ec2:DescribeInstances"],
    supported_services=["ec2"],
    mitre_techniques=["T1555.005", "T1530"],
    tags=["exfil", "ec2", "user-data", "secrets"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="ec2__exfil_ebs_snapshot",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Create EBS snapshot and share to attacker account for volume data exfiltration. DESTRUCTIVE.",
    required_permissions=["ec2:CreateSnapshot", "ec2:DescribeSnapshots", "ec2:ModifySnapshotAttribute", "ec2:DescribeVolumes", "ec2:DescribeInstances"],
    supported_services=["ec2"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["exfil", "ec2", "ebs", "snapshot", "cross-account", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2__exfil_ami",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Create AMI from instance and share to attacker account for full system exfiltration. DESTRUCTIVE.",
    required_permissions=["ec2:CreateImage", "ec2:DescribeImages", "ec2:ModifyImageAttribute", "ec2:DescribeInstances"],
    supported_services=["ec2"],
    mitre_techniques=["T1530", "T1020", "T1611"],
    tags=["exfil", "ec2", "ami", "system-image", "cross-account", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2__exfil_instance_metadata",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Extract EC2 instance metadata (IAM role credentials, user data, tags) via IMDS.",
    required_permissions=["ec2:DescribeInstances"],
    supported_services=["ec2"],
    mitre_techniques=["T1555.005", "T1530", "T1041"],
    tags=["exfil", "ec2", "metadata", "imds", "credentials"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="secretsmanager__exfil_secrets",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.CRITICAL,
    description="Extract secret values from Secrets Manager. CRITICAL - credential theft.",
    required_permissions=["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret", "secretsmanager:ListSecrets", "secretsmanager:ListSecretVersionIds"],
    supported_services=["secretsmanager"],
    mitre_techniques=["T1555.005", "T1530", "T1041"],
    tags=["exfil", "secretsmanager", "secrets", "credentials", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="parameter_store__exfil_parameters",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Extract SecureString parameters from SSM Parameter Store. DESTRUCTIVE.",
    required_permissions=["ssm:GetParameters", "ssm:GetParametersByPath", "ssm:DescribeParameters", "kms:Decrypt"],
    supported_services=["ssm", "kms"],
    mitre_techniques=["T1555.003", "T1530", "T1041"],
    tags=["exfil", "parameter-store", "ssm", "secrets", "credentials", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ecr__exfil_images",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Pull ECR container images for analysis/extraction. DESTRUCTIVE.",
    required_permissions=["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:ListImages", "ecr:DescribeRepositories", "ecr:BatchCheckLayerAvailability"],
    supported_services=["ecr"],
    mitre_techniques=["T1530", "T1020", "T1610"],
    tags=["exfil", "ecr", "container", "images", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="cloudtrail__exfil_logs",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Extract CloudTrail logs from S3 bucket for reconnaissance. DESTRUCTIVE.",
    required_permissions=["s3:GetObject", "s3:ListObjectsV2", "cloudtrail:DescribeTrails", "cloudtrail:LookupEvents"],
    supported_services=["cloudtrail", "s3"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["exfil", "cloudtrail", "logs", "reconnaissance", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="config__exfil_resources",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Extract AWS Config resource configurations and history.",
    required_permissions=["config:GetResourceConfigHistory", "config:ListDiscoveredResources", "config:DescribeConfigurationRecorders"],
    supported_services=["config"],
    mitre_techniques=["T1530", "T1020", "T1526"],
    tags=["exfil", "config", "resources", "inventory"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="sqs__exfil_messages",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Receive and extract messages from SQS queues. DESTRUCTIVE - consumes messages.",
    required_permissions=["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes", "sqs:ListQueues"],
    supported_services=["sqs"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["exfil", "sqs", "messages", "queue", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="kinesis__exfil_records",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Get records from Kinesis data streams for real-time exfiltration. DESTRUCTIVE.",
    required_permissions=["kinesis:GetRecords", "kinesis:GetShardIterator", "kinesis:DescribeStream", "kinesis:ListStreams"],
    supported_services=["kinesis"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["exfil", "kinesis", "stream", "real-time", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="efs__exfil_files",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Mount EFS and extract files. Requires EC2/ENI access. DESTRUCTIVE.",
    required_permissions=["elasticfilesystem:DescribeFileSystems", "elasticfilesystem:DescribeMountTargets", "ec2:CreateNetworkInterface", "ec2:AttachNetworkInterface"],
    supported_services=["efs", "ec2"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["exfil", "efs", "files", "mount", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="glue__exfil_catalog",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Extract Glue Data Catalog metadata (databases, tables, partitions).",
    required_permissions=["glue:GetDatabases", "glue:GetTables", "glue:GetPartitions", "glue:GetTableVersions"],
    supported_services=["glue"],
    mitre_techniques=["T1530", "T1020", "T1526"],
    tags=["exfil", "glue", "catalog", "metadata"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="athena__exfil_query_results",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Execute Athena queries and extract results from S3 for data exfiltration. DESTRUCTIVE.",
    required_permissions=["athena:StartQueryExecution", "athena:GetQueryResults", "athena:GetQueryExecution", "s3:GetObject", "s3:ListObjectsV2"],
    supported_services=["athena", "s3"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["exfil", "athena", "query", "sql", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="redshift__exfil_snapshot",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.CRITICAL,
    description="Create and share Redshift snapshot for data warehouse exfiltration. CRITICAL.",
    required_permissions=["redshift:CreateClusterSnapshot", "redshift:DescribeClusterSnapshots", "redshift:AuthorizeSnapshotAccess", "redshift:DescribeClusters"],
    supported_services=["redshift"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["exfil", "redshift", "snapshot", "data-warehouse", "cross-account", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="opensearch__exfil_snapshot",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Create and extract OpenSearch/Elasticsearch domain snapshots. DESTRUCTIVE.",
    required_permissions=["es:CreateElasticsearchDomainSnapshot", "es:DescribeElasticsearchDomainSnapshots", "es:ListDomainSnapshots", "es:DescribeElasticsearchDomain"],
    supported_services=["es"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["exfil", "opensearch", "elasticsearch", "snapshot", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# List all exfil modules
EXFIL_MODULES = [
    "s3__exfil_download_objects", "s3__exfil_bucket_sync", "s3__exfil_replication",
    "s3__exfil_presigned_urls", "s3__exfil_access_points", "s3__exfil_select_query",
    "dynamodb__exfil_scan_table", "dynamodb__exfil_export_table", "dynamodb__exfil_streams",
    "rds__exfil_snapshot", "rds__exfil_clone", "rds__exfil_data_api",
    "lambda__exfil_env_vars", "lambda__exfil_function_code", "lambda__exfil_layer_code",
    "ec2__exfil_user_data", "ec2__exfil_ebs_snapshot", "ec2__exfil_ami", "ec2__exfil_instance_metadata",
    "secretsmanager__exfil_secrets",
    "parameter_store__exfil_parameters",
    "ecr__exfil_images",
    "cloudtrail__exfil_logs",
    "config__exfil_resources",
    "sqs__exfil_messages",
    "kinesis__exfil_records",
    "efs__exfil_files",
    "glue__exfil_catalog",
    "athena__exfil_query_results",
    "redshift__exfil_snapshot",
    "opensearch__exfil_snapshot",
]

__all__ = ["EXFIL_MODULES"]
