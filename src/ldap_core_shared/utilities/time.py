"""LDAP Generalized Time Processing Utilities.

This module provides comprehensive LDAP time processing following X.680 GeneralizedTime
specifications with perl-ldap compatibility patterns for time conversion, validation,
and manipulation of LDAP timestamp attributes.

LDAP GeneralizedTime provides standardized time representation for directory entries,
operational attributes, and time-based operations essential for enterprise directory
management, auditing, and compliance scenarios.

Architecture:
    - GeneralizedTime: Main time representation and conversion class
    - LDAPTimeUtils: Utility functions for time processing
    - TimeZoneHandler: Time zone management and conversion
    - TimeValidator: Time format validation and compliance

Usage Example:
    >>> from ldap_core_shared.utilities.time import GeneralizedTime
    >>>
    >>> # Create from current time
    >>> gt = GeneralizedTime.now()
    >>> print(f"LDAP time: {gt.to_ldap_string()}")
    >>>
    >>> # Parse LDAP time string
    >>> gt2 = GeneralizedTime.from_ldap_string("20231225120000Z")
    >>> print(f"Python datetime: {gt2.to_datetime()}")
    >>>
    >>> # Time operations
    >>> if gt2.is_expired():
    ...     print("Time has passed")

References:
    - perl-ldap: lib/Net/LDAP/Util.pm (generalized_time_to_time, time_to_generalized_time)
    - X.680: Information Technology - Abstract Syntax Notation One (ASN.1)
    - RFC 4517: LDAP Syntaxes and Matching Rules
    - ISO 8601: Date and time representation standards
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional


class TimeFormat(Enum):
    """LDAP time format types."""

    GENERALIZED_TIME = "generalized_time"    # YYYYMMDDHHmmssZ format
    UTC_TIME = "utc_time"                   # YYMMDDHHmmssZ format (deprecated)
    UNIX_TIMESTAMP = "unix_timestamp"        # Seconds since epoch
    ISO_8601 = "iso_8601"                   # ISO 8601 format


class TimePrecision(Enum):
    """Time precision levels."""

    SECONDS = "seconds"          # YYYYMMDDHHMMSSZ
    MINUTES = "minutes"          # YYYYMMDDHHMM00Z
    HOURS = "hours"             # YYYYMMDDHH0000Z
    DAYS = "days"               # YYYYMMDD000000Z
    FRACTIONAL = "fractional"    # YYYYMMDDHHMMSS.fZ


class TimeZoneType(Enum):
    """Time zone representation types."""

    UTC = "utc"                 # Z suffix (UTC)
    OFFSET = "offset"           # +/-HHMM offset
    LOCAL = "local"             # No timezone (local time)


class GeneralizedTime:
    """LDAP GeneralizedTime representation and manipulation.

    This class provides comprehensive LDAP time processing capabilities
    following X.680 GeneralizedTime specifications with support for
    various time formats, precision levels, and timezone handling.

    Example:
        >>> # Current time
        >>> gt = GeneralizedTime.now()
        >>> ldap_str = gt.to_ldap_string()  # "20231225120000Z"
        >>>
        >>> # Parse LDAP time
        >>> gt2 = GeneralizedTime.from_ldap_string("20231225120000Z")
        >>> dt = gt2.to_datetime()
        >>>
        >>> # Time comparisons
        >>> if gt > gt2:
        ...     print("gt is later than gt2")
        >>>
        >>> # Time arithmetic
        >>> future = gt.add_days(30)
        >>> past = gt.subtract_hours(24)
    """

    # Regex patterns for LDAP time formats
    GENERALIZED_TIME_PATTERN = re.compile(
        r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?(Z|[+-]\d{4})?$",
    )

    UTC_TIME_PATTERN = re.compile(
        r"^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(Z|[+-]\d{4})?$",
    )

    def __init__(
        self,
        dt: Optional[datetime] = None,
        precision: TimePrecision = TimePrecision.SECONDS,
        timezone_type: TimeZoneType = TimeZoneType.UTC,
    ) -> None:
        """Initialize GeneralizedTime.

        Args:
            dt: Python datetime object (defaults to current UTC time)
            precision: Time precision level
            timezone_type: Timezone representation type
        """
        self._datetime = dt or datetime.now(timezone.utc)
        self._precision = precision
        self._timezone_type = timezone_type

        # Ensure datetime has timezone info
        if self._datetime.tzinfo is None:
            self._datetime = self._datetime.replace(tzinfo=timezone.utc)

    @classmethod
    def now(cls, precision: TimePrecision = TimePrecision.SECONDS) -> GeneralizedTime:
        """Create GeneralizedTime for current UTC time.

        Args:
            precision: Time precision level

        Returns:
            GeneralizedTime for current time
        """
        return cls(datetime.now(timezone.utc), precision, TimeZoneType.UTC)

    @classmethod
    def from_datetime(
        cls,
        dt: datetime,
        precision: TimePrecision = TimePrecision.SECONDS,
        timezone_type: TimeZoneType = TimeZoneType.UTC,
    ) -> GeneralizedTime:
        """Create GeneralizedTime from Python datetime.

        Args:
            dt: Python datetime object
            precision: Time precision level
            timezone_type: Timezone representation type

        Returns:
            GeneralizedTime object
        """
        return cls(dt, precision, timezone_type)

    @classmethod
    def from_ldap_string(cls, ldap_time: str) -> GeneralizedTime:
        """Parse LDAP GeneralizedTime string.

        Args:
            ldap_time: LDAP time string (e.g., "20231225120000Z")

        Returns:
            GeneralizedTime object

        Raises:
            ValueError: If time string format is invalid
        """
        # Try GeneralizedTime format first
        match = cls.GENERALIZED_TIME_PATTERN.match(ldap_time.strip())
        if match:
            year, month, day, hour, minute, second, fraction, tz = match.groups()

            # Convert to integers
            year = int(year)
            month = int(month)
            day = int(day)
            hour = int(hour)
            minute = int(minute)
            second = int(second)

            # Handle fractional seconds
            microsecond = 0
            if fraction:
                # Pad or truncate to 6 digits
                fraction = fraction.ljust(6, "0")[:6]
                microsecond = int(fraction)

            # Handle timezone
            tz_info: Optional[timezone] = timezone.utc
            timezone_type = TimeZoneType.UTC

            if tz and tz != "Z":
                # Parse offset (+/-HHMM)
                sign = 1 if tz[0] == "+" else -1
                hours = int(tz[1:3])
                minutes = int(tz[3:5])
                offset_minutes = sign * (hours * 60 + minutes)
                tz_info = timezone(timedelta(minutes=offset_minutes))
                timezone_type = TimeZoneType.OFFSET
            elif not tz:
                timezone_type = TimeZoneType.LOCAL
                tz_info = None

            # Create datetime
            dt = datetime(year, month, day, hour, minute, second, microsecond, tz_info)

            # Determine precision
            precision = TimePrecision.SECONDS
            if fraction:
                precision = TimePrecision.FRACTIONAL

            return cls(dt, precision, timezone_type)

        # Try UTCTime format (deprecated but still supported)
        match = cls.UTC_TIME_PATTERN.match(ldap_time.strip())
        if match:
            year, month, day, hour, minute, second, tz = match.groups()

            # Convert 2-digit year to 4-digit (assume 20xx for years < 50, 19xx for >= 50)
            year = int(year)
            if year < 50:
                year += 2000
            else:
                year += 1900

            month = int(month)
            day = int(day)
            hour = int(hour)
            minute = int(minute)
            second = int(second)

            # Handle timezone
            tz_info = timezone.utc
            timezone_type = TimeZoneType.UTC

            if tz and tz != "Z":
                sign = 1 if tz[0] == "+" else -1
                hours = int(tz[1:3])
                minutes = int(tz[3:5])
                offset_minutes = sign * (hours * 60 + minutes)
                tz_info = timezone(timedelta(minutes=offset_minutes))
                timezone_type = TimeZoneType.OFFSET
            elif not tz:
                timezone_type = TimeZoneType.LOCAL
                tz_info = None

            dt = datetime(year, month, day, hour, minute, second, 0, tz_info)
            return cls(dt, TimePrecision.SECONDS, timezone_type)

        msg = f"Invalid LDAP time format: {ldap_time}"
        raise ValueError(msg)

    @classmethod
    def from_unix_timestamp(cls, timestamp: float) -> GeneralizedTime:
        """Create GeneralizedTime from Unix timestamp.

        Args:
            timestamp: Unix timestamp (seconds since epoch)

        Returns:
            GeneralizedTime object
        """
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return cls(dt, TimePrecision.SECONDS, TimeZoneType.UTC)

    @classmethod
    def from_iso_string(cls, iso_string: str) -> GeneralizedTime:
        """Create GeneralizedTime from ISO 8601 string.

        Args:
            iso_string: ISO 8601 time string

        Returns:
            GeneralizedTime object
        """
        dt = datetime.fromisoformat(iso_string.replace("Z", "+00:00"))
        precision = TimePrecision.FRACTIONAL if "." in iso_string else TimePrecision.SECONDS
        return cls(dt, precision, TimeZoneType.UTC)

    def to_ldap_string(self, force_utc: bool = True) -> str:
        """Convert to LDAP GeneralizedTime string.

        Args:
            force_utc: Whether to convert to UTC before formatting

        Returns:
            LDAP GeneralizedTime string (e.g., "20231225120000Z")
        """
        dt = self._datetime

        # Convert to UTC if requested
        if force_utc and dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc)

        # Apply precision
        if self._precision == TimePrecision.DAYS:
            dt = dt.replace(hour=0, minute=0, second=0, microsecond=0)
        elif self._precision == TimePrecision.HOURS:
            dt = dt.replace(minute=0, second=0, microsecond=0)
        elif self._precision == TimePrecision.MINUTES:
            dt = dt.replace(second=0, microsecond=0)
        elif self._precision == TimePrecision.SECONDS:
            dt = dt.replace(microsecond=0)

        # Format base time
        time_str = dt.strftime("%Y%m%d%H%M%S")

        # Add fractional seconds if needed
        if self._precision == TimePrecision.FRACTIONAL and dt.microsecond > 0:
            fraction = f"{dt.microsecond:06d}".rstrip("0")
            time_str += f".{fraction}"

        # Add timezone
        if force_utc or self._timezone_type == TimeZoneType.UTC:
            time_str += "Z"
        elif self._timezone_type == TimeZoneType.OFFSET and dt.tzinfo:
            offset = dt.utcoffset()
            if offset:
                total_seconds = int(offset.total_seconds())
                hours, remainder = divmod(abs(total_seconds), 3600)
                minutes = remainder // 60
                sign = "+" if total_seconds >= 0 else "-"
                time_str += f"{sign}{hours:02d}{minutes:02d}"

        return time_str

    def to_datetime(self) -> datetime:
        """Convert to Python datetime object.

        Returns:
            Python datetime object
        """
        return self._datetime

    def to_unix_timestamp(self) -> float:
        """Convert to Unix timestamp.

        Returns:
            Unix timestamp (seconds since epoch)
        """
        return self._datetime.timestamp()

    def to_iso_string(self) -> str:
        """Convert to ISO 8601 string.

        Returns:
            ISO 8601 time string
        """
        return self._datetime.isoformat()

    def to_utc(self) -> GeneralizedTime:
        """Convert to UTC timezone.

        Returns:
            GeneralizedTime in UTC
        """
        if self._datetime.tzinfo is None:
            # Assume local time, convert to UTC
            utc_dt = self._datetime.replace(tzinfo=timezone.utc)
        else:
            utc_dt = self._datetime.astimezone(timezone.utc)

        return GeneralizedTime(utc_dt, self._precision, TimeZoneType.UTC)

    def to_local(self) -> GeneralizedTime:
        """Convert to local timezone.

        Returns:
            GeneralizedTime in local timezone
        """
        local_dt = self._datetime.astimezone()
        return GeneralizedTime(local_dt, self._precision, TimeZoneType.LOCAL)

    # Time arithmetic operations
    def add_years(self, years: int) -> GeneralizedTime:
        """Add years to time.

        Args:
            years: Number of years to add

        Returns:
            New GeneralizedTime object
        """
        new_year = self._datetime.year + years
        new_dt = self._datetime.replace(year=new_year)
        return GeneralizedTime(new_dt, self._precision, self._timezone_type)

    def add_months(self, months: int) -> GeneralizedTime:
        """Add months to time.

        Args:
            months: Number of months to add

        Returns:
            New GeneralizedTime object
        """
        year = self._datetime.year
        month = self._datetime.month + months

        # Handle month overflow
        while month > 12:
            month -= 12
            year += 1
        while month < 1:
            month += 12
            year -= 1

        # Handle day overflow for shorter months
        day = min(self._datetime.day, self._days_in_month(year, month))

        new_dt = self._datetime.replace(year=year, month=month, day=day)
        return GeneralizedTime(new_dt, self._precision, self._timezone_type)

    def add_days(self, days: int) -> GeneralizedTime:
        """Add days to time.

        Args:
            days: Number of days to add

        Returns:
            New GeneralizedTime object
        """
        new_dt = self._datetime + timedelta(days=days)
        return GeneralizedTime(new_dt, self._precision, self._timezone_type)

    def add_hours(self, hours: int) -> GeneralizedTime:
        """Add hours to time.

        Args:
            hours: Number of hours to add

        Returns:
            New GeneralizedTime object
        """
        new_dt = self._datetime + timedelta(hours=hours)
        return GeneralizedTime(new_dt, self._precision, self._timezone_type)

    def add_minutes(self, minutes: int) -> GeneralizedTime:
        """Add minutes to time.

        Args:
            minutes: Number of minutes to add

        Returns:
            New GeneralizedTime object
        """
        new_dt = self._datetime + timedelta(minutes=minutes)
        return GeneralizedTime(new_dt, self._precision, self._timezone_type)

    def add_seconds(self, seconds: int) -> GeneralizedTime:
        """Add seconds to time.

        Args:
            seconds: Number of seconds to add

        Returns:
            New GeneralizedTime object
        """
        new_dt = self._datetime + timedelta(seconds=seconds)
        return GeneralizedTime(new_dt, self._precision, self._timezone_type)

    def subtract_years(self, years: int) -> GeneralizedTime:
        """Subtract years from time."""
        return self.add_years(-years)

    def subtract_months(self, months: int) -> GeneralizedTime:
        """Subtract months from time."""
        return self.add_months(-months)

    def subtract_days(self, days: int) -> GeneralizedTime:
        """Subtract days from time."""
        return self.add_days(-days)

    def subtract_hours(self, hours: int) -> GeneralizedTime:
        """Subtract hours from time."""
        return self.add_hours(-hours)

    def subtract_minutes(self, minutes: int) -> GeneralizedTime:
        """Subtract minutes from time."""
        return self.add_minutes(-minutes)

    def subtract_seconds(self, seconds: int) -> GeneralizedTime:
        """Subtract seconds from time."""
        return self.add_seconds(-seconds)

    # Utility methods
    def is_expired(self, reference_time: Optional[GeneralizedTime] = None) -> bool:
        """Check if time is in the past.

        Args:
            reference_time: Reference time (defaults to current time)

        Returns:
            True if time is expired
        """
        ref = reference_time or GeneralizedTime.now()
        return self._datetime < ref._datetime

    def is_future(self, reference_time: Optional[GeneralizedTime] = None) -> bool:
        """Check if time is in the future.

        Args:
            reference_time: Reference time (defaults to current time)

        Returns:
            True if time is in the future
        """
        ref = reference_time or GeneralizedTime.now()
        return self._datetime > ref._datetime

    def time_until(self, target_time: GeneralizedTime) -> timedelta:
        """Calculate time until target time.

        Args:
            target_time: Target time

        Returns:
            Time difference as timedelta
        """
        return target_time._datetime - self._datetime

    def time_since(self, reference_time: GeneralizedTime) -> timedelta:
        """Calculate time since reference time.

        Args:
            reference_time: Reference time

        Returns:
            Time difference as timedelta
        """
        return self._datetime - reference_time._datetime

    def format_age(self, reference_time: Optional[GeneralizedTime] = None) -> str:
        """Format age relative to reference time.

        Args:
            reference_time: Reference time (defaults to current time)

        Returns:
            Human-readable age string
        """
        ref = reference_time or GeneralizedTime.now()
        delta = ref._datetime - self._datetime

        if delta.days > 365:
            years = delta.days // 365
            return f"{years} year{'s' if years != 1 else ''} ago"
        if delta.days > 30:
            months = delta.days // 30
            return f"{months} month{'s' if months != 1 else ''} ago"
        if delta.days > 0:
            return f"{delta.days} day{'s' if delta.days != 1 else ''} ago"
        if delta.seconds > 3600:
            hours = delta.seconds // 3600
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        if delta.seconds > 60:
            minutes = delta.seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        return "just now"

    def _days_in_month(self, year: int, month: int) -> int:
        """Get number of days in a month."""
        if month in {1, 3, 5, 7, 8, 10, 12}:
            return 31
        if month in {4, 6, 9, 11}:
            return 30
        # February
        return 29 if self._is_leap_year(year) else 28

    def _is_leap_year(self, year: int) -> bool:
        """Check if year is a leap year."""
        return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)

    # Comparison operators
    def __eq__(self, other: object) -> bool:
        """Check time equality."""
        if not isinstance(other, GeneralizedTime):
            return False
        return self._datetime == other._datetime

    def __lt__(self, other: Any) -> bool:
        """Check if time is less than other."""
        if not isinstance(other, GeneralizedTime):
            return NotImplemented
        return self._datetime < other._datetime

    def __le__(self, other: Any) -> bool:
        """Check if time is less than or equal to other."""
        if not isinstance(other, GeneralizedTime):
            return NotImplemented
        return self._datetime <= other._datetime

    def __gt__(self, other: Any) -> bool:
        """Check if time is greater than other."""
        if not isinstance(other, GeneralizedTime):
            return NotImplemented
        return self._datetime > other._datetime

    def __ge__(self, other: Any) -> bool:
        """Check if time is greater than or equal to other."""
        if not isinstance(other, GeneralizedTime):
            return NotImplemented
        return self._datetime >= other._datetime

    def __str__(self) -> str:
        """String representation."""
        return self.to_ldap_string()

    def __repr__(self) -> str:
        """Detailed string representation."""
        return f"GeneralizedTime('{self.to_ldap_string()}')"

    @property
    def precision(self) -> TimePrecision:
        """Get time precision."""
        return self._precision

    @property
    def timezone_type(self) -> TimeZoneType:
        """Get timezone type."""
        return self._timezone_type


class LDAPTimeUtils:
    """Utility functions for LDAP time processing."""

    @staticmethod
    def parse_any_time_format(time_str: str) -> GeneralizedTime:
        """Parse time string in any supported format.

        Args:
            time_str: Time string in various formats

        Returns:
            GeneralizedTime object

        Raises:
            ValueError: If no format matches
        """
        # Try LDAP GeneralizedTime format
        try:
            return GeneralizedTime.from_ldap_string(time_str)
        except ValueError:
            pass

        # Try ISO 8601 format
        try:
            return GeneralizedTime.from_iso_string(time_str)
        except ValueError:
            pass

        # Try Unix timestamp
        try:
            timestamp = float(time_str)
            return GeneralizedTime.from_unix_timestamp(timestamp)
        except ValueError:
            pass

        msg = f"Unsupported time format: {time_str}"
        raise ValueError(msg)

    @staticmethod
    def validate_ldap_time(time_str: str) -> bool:
        """Validate LDAP time string format.

        Args:
            time_str: Time string to validate

        Returns:
            True if format is valid
        """
        try:
            GeneralizedTime.from_ldap_string(time_str)
            return True
        except ValueError:
            return False

    @staticmethod
    def convert_time_format(
        time_str: str,
        target_format: TimeFormat = TimeFormat.GENERALIZED_TIME,
    ) -> str:
        """Convert time between different formats.

        Args:
            time_str: Source time string
            target_format: Target format

        Returns:
            Converted time string
        """
        gt = LDAPTimeUtils.parse_any_time_format(time_str)

        if target_format == TimeFormat.GENERALIZED_TIME:
            return gt.to_ldap_string()
        if target_format == TimeFormat.UNIX_TIMESTAMP:
            return str(int(gt.to_unix_timestamp()))
        if target_format == TimeFormat.ISO_8601:
            return gt.to_iso_string()
        msg = f"Unsupported target format: {target_format}"
        raise ValueError(msg)

    @staticmethod
    def get_expiry_time(
        duration_days: int,
        base_time: Optional[GeneralizedTime] = None,
    ) -> GeneralizedTime:
        """Calculate expiry time from duration.

        Args:
            duration_days: Duration in days
            base_time: Base time (defaults to current time)

        Returns:
            Expiry time
        """
        base = base_time or GeneralizedTime.now()
        return base.add_days(duration_days)

    @staticmethod
    def format_duration(delta: timedelta) -> str:
        """Format timedelta as human-readable duration.

        Args:
            delta: Time difference

        Returns:
            Formatted duration string
        """
        total_seconds = int(delta.total_seconds())

        if total_seconds < 60:
            return f"{total_seconds} seconds"
        if total_seconds < 3600:
            minutes = total_seconds // 60
            return f"{minutes} minutes"
        if total_seconds < 86400:
            hours = total_seconds // 3600
            return f"{hours} hours"
        days = total_seconds // 86400
        return f"{days} days"


# Convenience functions
def current_ldap_time() -> str:
    """Get current time as LDAP GeneralizedTime string.

    Returns:
        Current time in LDAP format
    """
    return GeneralizedTime.now().to_ldap_string()


def ldap_time_to_datetime(ldap_time: str) -> datetime:
    """Convert LDAP time string to Python datetime.

    Args:
        ldap_time: LDAP GeneralizedTime string

    Returns:
        Python datetime object
    """
    return GeneralizedTime.from_ldap_string(ldap_time).to_datetime()


def datetime_to_ldap_time(dt: datetime) -> str:
    """Convert Python datetime to LDAP time string.

    Args:
        dt: Python datetime object

    Returns:
        LDAP GeneralizedTime string
    """
    return GeneralizedTime.from_datetime(dt).to_ldap_string()


def is_time_expired(ldap_time: str, reference_time: Optional[str] = None) -> bool:
    """Check if LDAP time is expired.

    Args:
        ldap_time: LDAP time string to check
        reference_time: Reference time (defaults to current time)

    Returns:
        True if time is expired
    """
    gt = GeneralizedTime.from_ldap_string(ldap_time)
    ref = GeneralizedTime.from_ldap_string(reference_time) if reference_time else None
    return gt.is_expired(ref)


# TODO: Integration points for implementation:
#
# 1. Advanced Time Zone Handling:
#    - Comprehensive timezone database integration
#    - Daylight saving time calculations
#    - Regional time zone conversion utilities
#
# 2. LDAP Attribute Integration:
#    - Automatic time attribute processing
#    - Operational attribute time handling
#    - Schema-aware time validation
#
# 3. Time-Based Operations:
#    - Time-based search filters
#    - Expiry monitoring and alerting
#    - Time-based access control
#
# 4. Performance Optimization:
#    - Efficient time parsing and formatting
#    - Caching of timezone information
#    - Optimized time comparison operations
#
# 5. Compliance and Standards:
#    - Full X.680 GeneralizedTime compliance
#    - RFC 4517 syntax validation
#    - Cross-platform time handling
#
# 6. Integration with Directory Operations:
#    - Password expiry calculations
#    - Account lockout time management
#    - Audit trail timestamp processing
#
# 7. Testing Requirements:
#    - Unit tests for all time functionality
#    - Timezone conversion tests
#    - Edge case and boundary tests
#    - Performance tests for time operations
