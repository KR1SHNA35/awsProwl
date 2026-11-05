"""SQLAlchemy models for awsProwl sessions and AWS data."""

from __future__ import annotations

import copy
import datetime
import json
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    Text,
    inspect,
    orm,
    text,
)
from sqlalchemy.orm import Session, relationship
from sqlalchemy_utils import JSONType  # type: ignore

from awsprowl.core.base import Base, engine
from awsprowl.core.mixins import ModelUpdateMixin
from awsprowl.utils import remove_empty_from_dict

if TYPE_CHECKING:
    from awsprowl.core.session import ProwlSession


class AWSKey(Base, ModelUpdateMixin):
    """AWS credentials/keys associated with a session."""

    __tablename__ = "aws_key"

    id = Column(Integer, primary_key=True)

    session_id = Column(Integer, ForeignKey("prowl_session.id", ondelete="CASCADE"))
    session = relationship("ProwlSession", back_populates="aws_keys")

    user_name = Column(Text)
    role_name = Column(Text)
    arn = Column(Text)
    account_id = Column(Text)
    user_id = Column(Text)
    roles = Column(JSONType)
    groups = Column(JSONType)
    policies = Column(JSONType)
    access_key_id = Column(Text)
    secret_access_key = Column(Text)
    session_token = Column(Text)
    key_alias = Column(Text)
    permissions_confirmed = Column(JSONType)
    allow_permissions = Column(JSONType, nullable=False, default=dict)
    deny_permissions = Column(JSONType, nullable=False, default=dict)
    mq = Column(JSONType)
    sns = Column(JSONType)

    def __repr__(self) -> str:
        return f"<AWSKey #{self.id}: {self.key_alias}>"

    def get_fields_as_camel_case_dictionary(self) -> dict:
        """Return fields as camelCase dictionary for API/frontend consumption."""
        # Deep copy because Permissions->allow_permissions and deny_permissions were dicts that were being passed as reference
        return copy.deepcopy({
            "UserName": self.user_name,
            "RoleName": self.role_name,
            "Arn": self.arn,
            "AccountId": self.account_id,
            "UserId": self.user_id,
            "Roles": self.roles,
            "Groups": self.groups,
            "Policies": self.policies,
            "AccessKeyId": self.access_key_id,
            "SecretAccessKey": self.secret_access_key,
            "SessionToken": self.session_token,
            "KeyAlias": self.key_alias,
            "PermissionsConfirmed": self.permissions_confirmed,
            "Permissions": {
                "Allow": remove_empty_from_dict(self.allow_permissions),
                "Deny": remove_empty_from_dict(self.deny_permissions),
            },
        })


class ProwlSession(Base, ModelUpdateMixin):
    """Main session model for awsProwl, stores all gathered AWS data."""

    __tablename__ = "prowl_session"

    # AWS service data fields that can be populated during scans
    aws_data_field_names = (
        "APIGateway",
        "CloudTrail",
        "CloudWatch",
        "CodeBuild",
        "Cognito",
        "Config",
        "DataPipeline",
        "DynamoDB",
        "DS",
        "EC2",
        "ECS",
        "EKS",
        "Glue",
        "GuardDuty",
        "IAM",
        "Inspector",
        "Lambda",
        "Lightsail",
        "MQ",
        "S3",
        "SecretsManager",
        "Shield",
        "SNS",
        "SSM",
        "VPC",
        "WAF",
        "WAFRegional",
        "Account",
        "AccountSpend",
        "Route53",
        "RDS",
        "Transfer",
        "Organizations",
        "BeanStalk",
        "CloudFront",
        "KMS",
        "ElastiCache",
        "ELB",
        "ELBV2",
    )

    # Relationships
    aws_keys = relationship(
        "AWSKey",
        back_populates="session",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    # Core fields
    id = Column(Integer, primary_key=True)
    created = Column(DateTime, default=datetime.datetime.utcnow)
    is_active = Column(Boolean, nullable=False, default=False)
    name = Column(Text)
    boto_user_agent = Column(Text)
    user_agent_suffix = Column(Text)
    key_alias = Column(Text)
    access_key_id = Column(Text)
    secret_access_key = Column(Text)
    session_token = Column(Text)
    session_regions = Column(JSONType, nullable=False, default=["all"])

    # AWS Service Data (JSON columns)
    APIGateway = Column(JSONType, nullable=False, default=dict)
    CloudTrail = Column(JSONType, nullable=False, default=dict)
    CloudWatch = Column(JSONType, nullable=False, default=dict)
    CodeBuild = Column(JSONType, nullable=False, default=dict)
    Cognito = Column(JSONType, nullable=False, default=dict)
    Config = Column(JSONType, nullable=False, default=dict)
    DataPipeline = Column(JSONType, nullable=False, default=dict)
    DynamoDB = Column(JSONType, nullable=False, default=dict)
    DS = Column(JSONType, nullable=False, default=dict)
    EC2 = Column(JSONType, nullable=False, default=dict)
    ECS = Column(JSONType, nullable=False, default=dict)
    EKS = Column(JSONType, nullable=False, default=dict)
    Glue = Column(JSONType, nullable=False, default=dict)
    GuardDuty = Column(JSONType, nullable=False, default=dict)
    IAM = Column(JSONType, nullable=False, default=dict)
    Inspector = Column(JSONType, nullable=False, default=dict)
    Lambda = Column(JSONType, nullable=False, default=dict)
    Lightsail = Column(JSONType, nullable=False, default=dict)
    MQ = Column(JSONType, nullable=False, default=dict)
    S3 = Column(JSONType, nullable=False, default=dict)
    SecretsManager = Column(JSONType, nullable=False, default=dict)
    SNS = Column(JSONType, nullable=False, default=dict)
    SSM = Column(JSONType, nullable=False, default=dict)
    Shield = Column(JSONType, nullable=False, default=dict)
    VPC = Column(JSONType, nullable=False, default=dict)
    WAF = Column(JSONType, nullable=False, default=dict)
    WAFRegional = Column(JSONType, nullable=False, default=dict)
    Account = Column(JSONType, nullable=False, default=dict)
    AccountSpend = Column(JSONType, nullable=False, default=dict)
    Route53 = Column(JSONType, nullable=False, default=dict)
    RDS = Column(JSONType, nullable=False, default=dict)
    Transfer = Column(JSONType, nullable=False, default=dict)
    Organizations = Column(JSONType, nullable=False, default=dict)
    BeanStalk = Column(JSONType, nullable=False, default=dict)
    CloudFront = Column(JSONType, nullable=False, default=dict)
    KMS = Column(JSONType, nullable=False, default=dict)
    ElastiCache = Column(JSONType, nullable=False, default=dict)
    ELB = Column(JSONType, nullable=False, default=dict)
    ELBV2 = Column(JSONType, nullable=False, default=dict)

    def __repr__(self) -> str:
        if self.key_alias:
            key_alias = self.key_alias
        else:
            key_alias = "No Keys Set"
        if self.is_active:
            return f"<ProwlSession #{self.id} ({self.name}:{key_alias}) (ACTIVE)>"
        return f"<ProwlSession #{self.id} ({self.name}:{key_alias})>"

    @classmethod
    def get_active_session(cls, database: Session) -> ProwlSession | None:
        """Get the currently active session."""
        return database.query(ProwlSession).filter(ProwlSession.is_active == True).scalar()  # noqa: E712

    def get_active_aws_key(self, database: Session) -> AWSKey | None:
        """Return the AWSKey with the same key_alias as the ProwlSession."""
        return self.aws_keys.filter(AWSKey.key_alias == self.key_alias).scalar()

    def activate(self, database: orm.session.Session) -> None:
        """Set this session as the active session."""
        for other_session in database.query(ProwlSession).filter(ProwlSession.id != self.id):
            other_session.is_active = False
            database.add(other_session)

        self.is_active = True
        database.add(self)
        database.commit()

    def print_all_data_in_session(self) -> None:
        """Print all data stored in this session."""
        text_lines = []
        mapper = inspect(self)

        for column in mapper.attrs:
            cleaned_value = remove_empty_from_dict(column.value)

            if column.key == "aws_keys":
                owned_keys = column.value.all()
                if owned_keys:
                    text_lines.append("aws_keys: [")
                    for each_key in owned_keys:
                        text_lines.append(f"    <AWSKey: {each_key.key_alias}>")
                    text_lines.append("]")

            elif column.key == "secret_access_key":
                text_lines.append('secret_access_key: "******" (Censored)')

            elif cleaned_value:
                text_lines.append(f"{column.key}: {json.dumps(cleaned_value, indent=4, default=str)}")

        if text_lines:
            print("\n".join(text_lines))
        else:
            print("This session has no data.")

    def get_all_fields_as_dict(self) -> dict:
        """Get all fields as a dictionary."""
        all_data = {}
        mapper = inspect(self)
        for attribute in mapper.attrs:
            all_data[attribute.key] = attribute.value
        return all_data

    def get_all_aws_data_fields_as_dict(self) -> dict:
        """Get all AWS data fields as a dictionary."""
        all_data = {}
        mapper = inspect(self)

        for attribute in mapper.attrs:
            if attribute.key in self.aws_data_field_names:
                if attribute.value:
                    all_data[attribute.key] = attribute.value

        return remove_empty_from_dict(all_data)


def migrations(database: Session) -> None:
    """Run database migrations for the prowl_session table.

    Adds columns for any new AWS services added to aws_data_field_names.
    """
    rows = []
    for row in database.execute(text(f'pragma table_info({ProwlSession.__tablename__})')).fetchall():
        rows.append(row[1])

    # Add user_agent_suffix if missing
    if "user_agent_suffix" not in rows:
        column_type = ProwlSession.user_agent_suffix.type.compile(engine.dialect)
        database.execute(
            text(f"ALTER TABLE {ProwlSession.__tablename__} ADD COLUMN user_agent_suffix {column_type}")
        )

    # Add any missing AWS service data columns
    for svc in ProwlSession.aws_data_field_names:
        if svc not in rows:
            column = getattr(ProwlSession, svc)
            column_type = column.type.compile(engine.dialect)
            database.execute(
                text(
                    f"ALTER TABLE {ProwlSession.__tablename__} ADD COLUMN {svc} {column_type} DEFAULT '{{}}' NOT NULL"
                )
            )
