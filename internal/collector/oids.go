package collector

// OIDs derived directly from mibs/SOPHOS-XG-MIB.mib (SFOS-FIREWALL-MIB,
// revision 201812180000Z) plus the standard HOST-RESOURCES-MIB and IF-MIB.
//
// Enterprise base: sophosMIB 1.3.6.1.4.1.2604 -> sfosXGMIB .5 ->
// sfosXGMIBObjects 1.3.6.1.4.1.2604.5.1.
const (
	base = "1.3.6.1.4.1.2604.5.1"

	// 5.1 sfosXGDeviceInfo (.1) — DisplayString scalars.
	oidDeviceName      = base + ".1.1.0"
	oidDeviceType      = base + ".1.2.0"
	oidDeviceFWVersion = base + ".1.3.0"
	oidDeviceAppKey    = base + ".1.4.0"
	oidWebcatVersion   = base + ".1.5.0"
	oidIPSVersion      = base + ".1.6.0"

	// 5.2 sfosXGDeviceStats (.2).
	oidUpTime             = base + ".2.2.0" // TimeTicks (÷100 = seconds)
	oidDiskCapacity       = base + ".2.4.1.0"
	oidDiskPercentUsage   = base + ".2.4.2.0"
	oidMemoryCapacity     = base + ".2.5.1.0"
	oidMemoryPercentUsage = base + ".2.5.2.0"
	oidSwapCapacity       = base + ".2.5.3.0"
	oidSwapPercentUsage   = base + ".2.5.4.0"
	oidLiveUsersCount     = base + ".2.6.0"
	oidHTTPHits           = base + ".2.7.0"   // Counter64
	oidFTPHits            = base + ".2.8.0"   // Counter64
	oidPOP3Hits           = base + ".2.9.1.0" // Counter64
	oidImapHits           = base + ".2.9.2.0" // Counter64
	oidSmtpHits           = base + ".2.9.3.0" // Counter64

	// 5.3 sfosXGServiceStatus (.3) — 21 scalars at .3.<n>.0.
	oidServiceBase = base + ".3"

	// 5.4 sfosXGHAStats (.4).
	oidHAStatus       = base + ".4.1.0" // disabled(0) enabled(1)
	oidHACurrentState = base + ".4.4.0" // HaState enum

	// 5.5 sfosXGLicenseDetails (.5) — 9 modules; .<n>.1 status, .<n>.2 expiry.
	oidLicenseBase = base + ".5"

	// 5.7 sfosXGTunnelInfo (.6) — IPsec tunnel table entry columns.
	oidIPSecTunnelEntry = base + ".6.1.1.1"
	oidVPNConnName      = oidIPSecTunnelEntry + ".2" // DisplayString
	oidVPNConnMode      = oidIPSecTunnelEntry + ".5" // DisplayString
	oidVPNConnType      = oidIPSecTunnelEntry + ".6" // IPSecVPNConnectionType enum
	oidVPNActiveTunnel  = oidIPSecTunnelEntry + ".8" // Integer32
	oidVPNConnStatus    = oidIPSecTunnelEntry + ".9" // IPSecVPNConnectionStatus enum

	// HOST-RESOURCES-MIB::hrProcessorLoad — walk, per-core CPU (Integer 0..100).
	oidHrProcessorLoad = "1.3.6.1.2.1.25.3.3.1.2"
)

// IF-MIB columns (walk; 64-bit HC counters where available).
const (
	oidIfName        = "1.3.6.1.2.1.31.1.1.1.1"  // ifName (label)
	oidIfHCInOctets  = "1.3.6.1.2.1.31.1.1.1.6"  // Counter64
	oidIfHCOutOctets = "1.3.6.1.2.1.31.1.1.1.10" // Counter64
	oidIfHCInUcast   = "1.3.6.1.2.1.31.1.1.1.7"  // Counter64
	oidIfHCOutUcast  = "1.3.6.1.2.1.31.1.1.1.11" // Counter64
	oidIfInErrors    = "1.3.6.1.2.1.2.2.1.14"    // Counter32
	oidIfOutErrors   = "1.3.6.1.2.1.2.2.1.20"    // Counter32
	oidIfOperStatus  = "1.3.6.1.2.1.2.2.1.8"     // up(1) down(2) ...
)

// bytesPerMB converts the SFOS capacity scalars (reported in MB — verify against
// a live snmpget per contract D6) to Prometheus base-unit bytes.
const bytesPerMB = 1024 * 1024
