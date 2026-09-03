# -*- coding: utf-8 -*-
"""
Validation Rule: Filter Port Range Validation

Ensures that filter entries with port specifications follow these rules:
1. If to_port is specified, from_port must also be specified (to_port without from_port is invalid)
2. If both from and to ports are specified, from must be less than or equal to to (logical range)

Note: from_port can be specified without to_port - the module defaults to_port to from_port value.
"""

# Port name to number mapping for comparison
PORT_NAME_MAP = {
    "unspecified": 0,
    "ftpData": 20,
    "smtp": 25,
    "dns": 53,
    "http": 80,
    "pop3": 110,
    "https": 443,
    "rtsp": 554,
    "ssh": 22,
}


class Rule:
    id = "310"
    description = (
        "Verify filter port ranges are valid (to_port requires from_port, from <= to)"
    )
    severity = "HIGH"

    @classmethod
    def _normalize_port(cls, port_value):
        """Convert port value to integer for comparison."""
        if port_value is None:
            return None
        if isinstance(port_value, int):
            return port_value
        if isinstance(port_value, str):
            return PORT_NAME_MAP.get(port_value.lower(), port_value)
        return port_value

    @classmethod
    def match(cls, inventory):
        results = []

        # Check APIC tenants
        tenants = inventory.get("apic", {}).get("tenants", [])
        if tenants is None:
            tenants = []

        for tenant in tenants:
            tenant_name = tenant.get("name", "unknown")
            filters = tenant.get("filters", [])
            if filters is None:
                filters = []

            for filter_obj in filters:
                filter_name = filter_obj.get("name", "unknown")
                entries = filter_obj.get("entries", [])
                if entries is None:
                    entries = []

                for entry in entries:
                    entry_name = entry.get("name", "unknown")
                    path = f"apic.tenants[{tenant_name}].filters[{filter_name}].entries[{entry_name}]"

                    # Check source ports
                    src_from = entry.get("source_from_port")
                    src_to = entry.get("source_to_port")

                    # Only flag if to_port is specified without from_port
                    # (from_port without to_port is OK - module defaults to_port to from_port)
                    if src_from is None and src_to is not None:
                        results.append(
                            f"{path} - source_to_port is specified ({src_to}) but source_from_port is missing. "
                            f"source_from_port must be specified to define a valid port range."
                        )
                    elif src_from is not None and src_to is not None:
                        src_from_norm = cls._normalize_port(src_from)
                        src_to_norm = cls._normalize_port(src_to)

                        if isinstance(src_from_norm, int) and isinstance(
                            src_to_norm, int
                        ):
                            if src_from_norm > src_to_norm:
                                results.append(
                                    f"{path} - source_from_port ({src_from}) is greater than source_to_port ({src_to}). "
                                    f"From port must be less than or equal to to port."
                                )

                    # Check destination ports
                    dst_from = entry.get("destination_from_port")
                    dst_to = entry.get("destination_to_port")

                    # Only flag if to_port is specified without from_port
                    # (from_port without to_port is OK - module defaults to_port to from_port)
                    if dst_from is None and dst_to is not None:
                        results.append(
                            f"{path} - destination_to_port is specified ({dst_to}) but destination_from_port is missing. "
                            f"destination_from_port must be specified to define a valid port range."
                        )
                    elif dst_from is not None and dst_to is not None:
                        dst_from_norm = cls._normalize_port(dst_from)
                        dst_to_norm = cls._normalize_port(dst_to)

                        if isinstance(dst_from_norm, int) and isinstance(
                            dst_to_norm, int
                        ):
                            if dst_from_norm > dst_to_norm:
                                results.append(
                                    f"{path} - destination_from_port ({dst_from}) is greater than destination_to_port ({dst_to}). "
                                    f"From port must be less than or equal to to port."
                                )

        return results
