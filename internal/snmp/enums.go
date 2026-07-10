package snmp

// Enum value tables decoded straight from SOPHOS-XG-MIB.mib. The collectors emit
// the raw integer as the metric value; these names are available for logging and
// optional label decoration.

// ServiceStatus is the SFOS ServiceStatsType enumeration.
type ServiceStatus int

// ServiceStatus values.
const (
	ServiceUntouched    ServiceStatus = 0
	ServiceStopped      ServiceStatus = 1
	ServiceInitializing ServiceStatus = 2
	ServiceRunning      ServiceStatus = 3
	ServiceExiting      ServiceStatus = 4
	ServiceDead         ServiceStatus = 5
	ServiceFrozen       ServiceStatus = 6
	ServiceUnregistered ServiceStatus = 7
)

var serviceStatusNames = map[ServiceStatus]string{
	ServiceUntouched:    "untouched",
	ServiceStopped:      "stopped",
	ServiceInitializing: "initializing",
	ServiceRunning:      "running",
	ServiceExiting:      "exiting",
	ServiceDead:         "dead",
	ServiceFrozen:       "frozen",
	ServiceUnregistered: "unregistered",
}

// String returns the enum name, or "unknown" for out-of-range values.
func (s ServiceStatus) String() string {
	if n, ok := serviceStatusNames[s]; ok {
		return n
	}
	return "unknown"
}

// IsRunning reports whether the service is in the running(3) state.
func (s ServiceStatus) IsRunning() bool { return s == ServiceRunning }

// LicenseStatus is the SFOS SubscriptionStatusType enumeration.
type LicenseStatus int

// LicenseStatus values.
const (
	LicenseNone          LicenseStatus = 0
	LicenseEvaluating    LicenseStatus = 1
	LicenseNotSubscribed LicenseStatus = 2
	LicenseSubscribed    LicenseStatus = 3
	LicenseExpired       LicenseStatus = 4
	LicenseDeactivated   LicenseStatus = 5
)

var licenseStatusNames = map[LicenseStatus]string{
	LicenseNone:          "none",
	LicenseEvaluating:    "evaluating",
	LicenseNotSubscribed: "notsubscribed",
	LicenseSubscribed:    "subscribed",
	LicenseExpired:       "expired",
	LicenseDeactivated:   "deactivated",
}

// String returns the enum name, or "unknown" for out-of-range values.
func (s LicenseStatus) String() string {
	if n, ok := licenseStatusNames[s]; ok {
		return n
	}
	return "unknown"
}

// VPNConnType is the SFOS IPSecVPNConnectionType enumeration.
type VPNConnType int

// VPNConnType values.
const (
	VPNHostToHost      VPNConnType = 1
	VPNSiteToSite      VPNConnType = 2
	VPNTunnelInterface VPNConnType = 3
)

var vpnConnTypeNames = map[VPNConnType]string{
	VPNHostToHost:      "host-to-host",
	VPNSiteToSite:      "site-to-site",
	VPNTunnelInterface: "tunnel-interface",
}

// String returns the enum name, or "unknown" for out-of-range values.
func (t VPNConnType) String() string {
	if n, ok := vpnConnTypeNames[t]; ok {
		return n
	}
	return "unknown"
}

// HAState is the SFOS HaState enumeration.
type HAState int

// HAState values.
const (
	HANotApplicable HAState = 0
	HAAuxiliary     HAState = 1
	HAStandAlone    HAState = 2
	HAPrimary       HAState = 3
	HAFaulty        HAState = 4
	HAReady         HAState = 5
)

var haStateNames = map[HAState]string{
	HANotApplicable: "notApplicable",
	HAAuxiliary:     "auxiliary",
	HAStandAlone:    "standAlone",
	HAPrimary:       "primary",
	HAFaulty:        "faulty",
	HAReady:         "ready",
}

// String returns the enum name, or "unknown" for out-of-range values.
func (s HAState) String() string {
	if n, ok := haStateNames[s]; ok {
		return n
	}
	return "unknown"
}
