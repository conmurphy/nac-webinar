class Rule:
    id = "03"
    description = "Verify unique EPG name"
    severity = "HIGH"

    @classmethod
    def match(cls, inventory):
        results = []
        try:
            tenants = inventory.get("apic", {}).get("tenants", [])
            if tenants is None:
                tenants = []
            for tenant in tenants:
                application_profiles = tenant.get("application_profiles", [])
                if application_profiles is None:
                    application_profiles = []

                for app in application_profiles:
                    regular_epg_names = []
                    useg_epg_names = []
                    regular_epgs = app.get("endpoint_groups", [])
                    if regular_epgs is None:
                        regular_epgs = []
                    useg_epgs = app.get("useg_endpoint_groups", [])
                    if useg_epgs is None:
                        useg_epgs = []

                    for epg in regular_epgs:
                        regular_epg_names.append(epg.get("name"))

                    for useg_epg in useg_epgs:
                        useg_epg_names.append(useg_epg.get("name"))

                    for k in regular_epg_names:
                        for v in useg_epg_names:
                            if k == v:
                                results.append(
                                    "Regular EPG and uSeg EPG have duplicated name - "
                                    + str(k)
                                    + " in application profile "
                                    + app.get("name")
                                    + " of tenant "
                                    + tenant.get("name")
                                )

        except KeyError:
            pass
        return results
