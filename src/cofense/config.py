"""Config models"""

from datetime import timedelta

from pydantic import BaseModel, BaseSettings, Field, validator

__all__ = [
    "RootConfig",
]


def validate_bool(*field_names):
    """Validation helper for converting bool fields"""

    def convert_bool(value: str) -> bool:
        """Convert a truthy/falsy value to a bool"""

        if isinstance(value, bool):
            return value

        lowered = value.lower()
        if lowered in ["true", "t", "1"]:
            return True
        elif lowered in ["false", "f", "0"]:
            return False
        else:
            raise ValueError(f"Invalid bool: {value}")

    return validator(*field_names, pre=True, allow_reuse=True)(convert_bool)


class ConnectorConfig(BaseSettings):
    """Connector config"""

    update_existing_data: bool = Field(
        description="Update existing data bundle flag",
        env="CONNECTOR_UPDATE_EXISTING_DATA",
        default=True,
    )
    interval: int = Field(
        description="Interval in minutes between runs",
        env="CONNECTOR_INTERVAL",
        default=86_400,
        ge=1,
    )
    loop_interval: int = Field(
        description="Interval in minutes between loops",
        env="CONNECTOR_LOOP_INTERVAL",
        default=60,
        ge=1,
    )

    _validate_bools = validate_bool("update_existing_data")


class CofenseConfig(BaseSettings):
    """Cofense config"""

    api_url: str = Field(
        description="Cofense ThreatHQ API Base URL",
        env="COFENSE_API_URL",
        default="https://www.threathq.com/apiv1",
    )
    api_user: str = Field(
        description="Cofense ThreatHQ API Username",
        env="COFENSE_API_USER",
    )
    api_pass: str = Field(
        description="Cofense ThreatHQ API Password",
        env="COFENSE_API_PASS",
    )
    verify: bool = Field(
        description="Verify SSL connections to the Cofense API",
        env="COFENSE_VERIFY",
        default=True,
    )
    create_indicators: bool = Field(
        description="Create indicators from observables",
        env="COFENSE_CREATE_INDICATORS",
        default=True,
    )
    create_ip_indicators: bool = Field(
        description="Create IP indicators from observables",
        env="COFENSE_CREATE_IP_INDICATORS",
        default=False,
    )
    ip_indicator_valid_until: timedelta = Field(
        description="ISO8601 time-delta for how long indicators should be valid",
        env="COFENSE_INDICATOR_VALID_UNTIL",
        default=timedelta(days=90),
    )

    _validate_bools = validate_bool(
        "verify",
        "create_indicators",
        "create_ip_indicators",
    )


class RootConfig(BaseModel):
    """Root config"""

    connector: ConnectorConfig = Field(default_factory=lambda: ConnectorConfig())
    Cofense: CofenseConfig = Field(default_factory=lambda: CofenseConfig())