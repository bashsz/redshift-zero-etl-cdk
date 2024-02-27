
import aws_cdk as cdk

from aws_cdk import (
    CfnOutput,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_kinesis as kinesis,
    aws_rds as rds,
    aws_redshift as redshift,
    aws_redshiftserverless as redshiftserverless,
    aws_lambda as _lambda,
    aws_logs as logs,
    Duration, RemovalPolicy, Stack
)
from constructs import Construct
from aws_cdk.custom_resources import Provider
from aws_cdk.aws_logs import RetentionDays


class DataFederateStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Applying default props
        props = {
            'databaseName': kwargs.get('databaseName', 'dev'),
            'adminUsername': kwargs.get('adminUsername', 'awsuser'),
            'adminPassword': kwargs.get('adminPassword', 'Unix_bb1831!!'),
            'baseRpu': kwargs.get('baseRpu', 128),
            'portNumber': kwargs.get('portNumber', 5439),
            'rdsdbPort': kwargs.get('rdsdbPort', 3306),
            'rdsMinCapacity': kwargs.get('rdsMinCapacity', '2'),
            'rdsMaxCapacity': kwargs.get('rdsMaxCapacity', '16'),
            'rdsSnapshotRetentionDays': kwargs.get('rdsSnapshotRetentionDays', '30')
        }

        # Resources
        customizedParameterGroup = redshift.CfnClusterParameterGroup(self, 'CustomizedParameterGroup',
            description = 'Customizations to parameter group for case sensitive id',
            parameter_group_family = 'redshift-1.0',
            parameter_group_name = 'ZeroETLrspg',
            parameters = [
                {
                'parameterName': 'enable_case_sensitive_identifier',
                'parameterValue': 'true',
                },
            ],
            )
        
        # Create public subnets
        public_subnets = ec2.SubnetConfiguration(
            subnet_type=ec2.SubnetType.PUBLIC, 
            name="Public",
            cidr_mask=24,
        )

        # Create private subnets  
        private_subnets = ec2.SubnetConfiguration(
            subnet_type=ec2.SubnetType.PRIVATE_WITH_NAT,
            name="Private", 
            cidr_mask=24
        )

        # Create a VPC with 3 AZs
        vpc = ec2.Vpc(
            self,
            "FederatedDataVPC",
            ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/16"),
            max_azs=3,
            nat_gateways=3,
            enable_dns_hostnames = True,
            enable_dns_support = True,
        )

        private_subnets = vpc.private_subnets

        redshift_sg = ec2.SecurityGroup(
            self, "RedshiftSecurityGroup",
            description="Allow access to Redshift cluster",
            vpc=vpc  
        )

        redshift_sg.add_ingress_rule(
            ec2.Peer.any_ipv4(), 
            ec2.Port.tcp(5439)
        )

        # Create Aurora Serverless MySQL security group  
        aurora_sg = ec2.SecurityGroup(
            self, "AuroraServerlessSecurityGroup",
            description="Allow access to Aurora Serverless",
            vpc=vpc,
        )

        aurora_sg.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(3306)  
        )

        redshift_role = iam.Role(
            self,
            "RedshiftRole",
            assumed_by=iam.ServicePrincipal(
                "redshift.amazonaws.com"
            ),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AmazonS3FullAccess"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AWSGlueConsoleFullAccess"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AmazonRedshiftFullAccess"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AmazonRDSFullAccess"
                ),
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AmazonKinesisFullAccess"
                ),
            ],
        )

        rds_role = iam.Role(
            self,
            "RDSRole",
            assumed_by=iam.ServicePrincipal(
                "rds.amazonaws.com"
            ),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AmazonS3FullAccess"
                )
            ],
        )

        rdsdbSubnetGroup = rds.CfnDBSubnetGroup(self, 'RDSDBSubnetGroup',
          db_subnet_group_description = 'Subnets the database belongs to',
          subnet_ids = [
            private_subnets[0].subnet_id,
            private_subnets[1].subnet_id,
          ],
          tags = [
            {
              'key': 'Application',
              'value': self.stack_id,
            },
          ],
        )

        parameter_group = rds.ParameterGroup(self, "ParameterGroup",
            engine=rds.DatabaseClusterEngine.aurora_mysql(
                version=rds.AuroraMysqlEngineVersion.VER_3_05_1
            )  
        )
        parameter_group.add_parameter("time_zone", "UTC")
        parameter_group.add_parameter("aws_default_s3_role", rds_role.role_arn)
        parameter_group.add_parameter("aurora_enhanced_binlog", "1")
        parameter_group.add_parameter("binlog_backup", "0")
        parameter_group.add_parameter("binlog_format", "ROW")
        parameter_group.add_parameter("binlog_replication_globaldb", "0")
        parameter_group.add_parameter("binlog_row_image", "full")
        parameter_group.add_parameter("binlog_row_metadata", "full")

        database = rds.DatabaseCluster(
            self,
            "RDSCluster",
            default_database_name=f"""{self.stack_name}""",
            engine=rds.DatabaseClusterEngine.aurora_mysql(version=rds.AuroraMysqlEngineVersion.VER_3_05_1),
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            deletion_protection=False,
            cloudwatch_logs_retention=RetentionDays.ONE_MONTH,
            storage_type=rds.DBClusterStorageType.AURORA_IOPT1,
            removal_policy=RemovalPolicy.DESTROY,
            credentials=rds.Credentials.from_password(
                username=props['adminUsername'],
                password=cdk.SecretValue.unsafe_plain_text(props['adminPassword']) 
            ),
            parameter_group=parameter_group,
            security_groups=[aurora_sg],
            writer=rds.ClusterInstance.provisioned("writer", publicly_accessible=False, 
                instance_type=ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE)
            ),
            readers=[
                rds.ClusterInstance.provisioned(
                    "reader1", publicly_accessible=False, instance_type=ec2.InstanceType.of(
                        ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
                    )
                )
            ],
        )


        db_cluster_arn = "arn:aws:rds:{}:{}:cluster:{}".format(
            self.region, self.account, database.cluster_identifier
        )

        redshiftClusterSubnetGroup = redshift.CfnClusterSubnetGroup(self, 'RedshiftClusterSubnetGroup',
            description = 'Cluster subnet group',
            subnet_ids = [
                private_subnets[0].subnet_id,
                private_subnets[1].subnet_id,
            ],
        )


        # Create a Kinesis Data Stream
        kinesis_stream = kinesis.Stream(
            self,
            "WearablesStream",
            shard_count=1,
            retention_period=cdk.Duration.days(7),
        )

        # Create a Redshift Serverless namespace and workgroup
        redshift_ns = redshiftserverless.CfnNamespace(
            self,
            "RedshiftNS",
            admin_username = props["adminUsername"],
            admin_user_password =props['adminPassword'],
            db_name = props["databaseName"],
            namespace_name = "redshift-dw-ns",
            iam_roles = [redshift_role.role_arn],
            default_iam_role_arn = redshift_role.role_arn,
        )
        

        redshift_wg = redshiftserverless.CfnWorkgroup(
            self,
            "RedshiftServerlessWorkgroup",
            namespace_name=redshift_ns.attr_namespace_namespace_name,
            workgroup_name="redshift-dw-wg",
            security_group_ids=[redshift_sg.security_group_id],
            subnet_ids=[
                private_subnets[0].subnet_id,
                private_subnets[1].subnet_id,
                private_subnets[2].subnet_id,
            ],
            config_parameters=[redshiftserverless.CfnWorkgroup.ConfigParameterProperty(
                parameter_key="enable_case_sensitive_identifier",
                parameter_value="true"
            )],
        )


        # Lambda Function
        custom_resource_lambda = _lambda.Function(
            self, "CustomResourceLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="custom_resource.handler",
            code=_lambda.Code.from_asset("lambda"),
            timeout=Duration.seconds(300),  # Adjust timeout as needed
            log_retention=logs.RetentionDays.ONE_WEEK,  # Adjust retention as needed
            initial_policy=[
                iam.PolicyStatement(
                    actions=["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                    resources=["*"]
                )
            ],
            environment={
                "VPC_ID": vpc.vpc_id,
                # Pass any other parameters as needed
            }
        )

        # Grant necessary permissions to the Lambda function
        custom_resource_lambda.add_to_role_policy(
            statement=iam.PolicyStatement(
                actions=[
                    "cloudformation:DescribeStacks",
                    "cloudformation:DescribeStackEvents",
                    "cloudformation:DescribeStackResource",
                    "cloudformation:DescribeStackResources",
                    "cloudformation:GetTemplate",
                    "cloudformation:ListStackResources",
                    "cloudformation:SignalResource",
                    "cloudformation:UpdateStack",
                    "redshift:*",
                    "rds:*"
                ],
                resources=["*"]
            )
        )

        custom_resource_lambda.node.add_dependency(redshift_wg)
        custom_resource_lambda.node.add_dependency(database)

        provider = Provider(scope=self, 
                            id=f'{id}Provider', 
                            on_event_handler=custom_resource_lambda)
        
        cdk.CustomResource(scope=self,
            id=f'{id}ZeroETLHandler',
            service_token=provider.service_token,
            removal_policy=RemovalPolicy.DESTROY,
            resource_type="Custom::ZeroETLHandler",
            properties={
                "source_arn_value":  db_cluster_arn,
                "target_arn_value":  redshift_ns.attr_namespace_namespace_arn
            },)

        
        CfnOutput(self, "RedshiftEndpoint", value=redshift_wg.attr_workgroup_endpoint_address)
        CfnOutput(self, "KinesisStream", value=kinesis_stream.stream_name)
        CfnOutput(self, "RDSEndpoint", value=database.cluster_endpoint.hostname)
