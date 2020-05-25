package ip

const (
	// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
	PROTO_ICMP            Protocol = 1
	PROTO_IGMP            Protocol = 2
	PROTO_GGP             Protocol = 3
	PROTO_IPv4            Protocol = 4
	PROTO_ST              Protocol = 5
	PROTO_TCP             Protocol = 6
	PROTO_CBT             Protocol = 7
	PROTO_EGP             Protocol = 8
	PROTO_IGP             Protocol = 9
	PROTO_BBN_RCC_MON     Protocol = 10
	PROTO_NVP_II          Protocol = 11
	PROTO_PUP             Protocol = 12
	PROTO_ARGUS           Protocol = 13
	PROTO_EMCON           Protocol = 14
	PROTO_XNET            Protocol = 15
	PROTO_CHAOS           Protocol = 16
	PROTO_UDP             Protocol = 17
	PROTO_MUX             Protocol = 18
	PROTO_DCN_MEAS        Protocol = 19
	PROTO_HMP             Protocol = 20
	PROTO_PRM             Protocol = 21
	PROTO_XNS_IDP         Protocol = 22
	PROTO_TRUNK_1         Protocol = 23
	PROTO_TRUNK_2         Protocol = 24
	PROTO_LEAF_1          Protocol = 25
	PROTO_LEAF_2          Protocol = 26
	PROTO_RDP             Protocol = 27
	PROTO_IRTP            Protocol = 28
	PROTO_ISO_TP4         Protocol = 29
	PROTO_NETBLT          Protocol = 30
	PROTO_MFE_NSP         Protocol = 31
	PROTO_MERIT_INP       Protocol = 32
	PROTO_DCCP            Protocol = 33
	PROTO_3PC             Protocol = 34
	PROTO_IDPR            Protocol = 35
	PROTO_XTP             Protocol = 36
	PROTO_DDP             Protocol = 37
	PROTO_IDPR_CMTP       Protocol = 38
	PROTO_TP_PP           Protocol = 39
	PROTO_IL              Protocol = 40
	PROTO_IPv6            Protocol = 41
	PROTO_SDRP            Protocol = 42
	PROTO_IPv6_Route      Protocol = 43
	PROTO_IPv6_Frag       Protocol = 44
	PROTO_IDRP            Protocol = 45
	PROTO_RSVP            Protocol = 46
	PROTO_GRE             Protocol = 47
	PROTO_DSR             Protocol = 48
	PROTO_BNA             Protocol = 49
	PROTO_ESP             Protocol = 50
	PROTO_AH              Protocol = 51
	PROTO_I_NLSP          Protocol = 52
	PROTO_SWIPE           Protocol = 53
	PROTO_NARP            Protocol = 54
	PROTO_MOBILE          Protocol = 55
	PROTO_TLSP            Protocol = 56
	PROTO_SKIP            Protocol = 57
	PROTO_IPv6_ICMP       Protocol = 58
	PROTO_IPv6_NoNxt      Protocol = 59
	PROTO_IPv6_Opts       Protocol = 60
	PROTO_CFTP            Protocol = 62
	PROTO_SAT_EXPAK       Protocol = 64
	PROTO_KRYPTOLAN       Protocol = 65
	PROTO_RVDMIT          Protocol = 66
	PROTO_IPPC            Protocol = 67
	PROTO_SAT_MON         Protocol = 69
	PROTO_VISA            Protocol = 70
	PROTO_IPCV            Protocol = 71
	PROTO_CPNX            Protocol = 72
	PROTO_CPHB            Protocol = 73
	PROTO_WSN             Protocol = 74
	PROTO_PVP             Protocol = 75
	PROTO_BR_SAT_MON      Protocol = 76
	PROTO_SUN_ND          Protocol = 77
	PROTO_WB_MON          Protocol = 78
	PROTO_WB_EXPAK        Protocol = 79
	PROTO_ISO_IP          Protocol = 80
	PROTO_VMTP            Protocol = 81
	PROTO_SECURE_VMTP     Protocol = 82
	PROTO_VINES           Protocol = 83
	PROTO_TTP             Protocol = 84
	PROTO_IPTM            Protocol = 84
	PROTO_NSFNET_IGP      Protocol = 85
	PROTO_DGP             Protocol = 86
	PROTO_TCF             Protocol = 87
	PROTO_EIGRP           Protocol = 88
	PROTO_OSPFIGP         Protocol = 89
	PROTO_Sprite_RPC      Protocol = 90
	PROTO_LARP            Protocol = 91
	PROTO_MTP             Protocol = 92
	PROTO_AX_25           Protocol = 93
	PROTO_IPIP            Protocol = 94
	PROTO_MICP            Protocol = 95
	PROTO_SCC_SP          Protocol = 96
	PROTO_ETHERIP         Protocol = 97
	PROTO_ENCAP           Protocol = 98
	PROTO_GMTP            Protocol = 100
	PROTO_IFMP            Protocol = 101
	PROTO_PNNI            Protocol = 102
	PROTO_PIM             Protocol = 103
	PROTO_ARIS            Protocol = 104
	PROTO_SCPS            Protocol = 105
	PROTO_QNX             Protocol = 106
	PROTO_A_N             Protocol = 107
	PROTO_IPComp          Protocol = 108
	PROTO_SNP             Protocol = 109
	PROTO_Compaq_Peer     Protocol = 110
	PROTO_IPX_in_IP       Protocol = 111
	PROTO_VRRP            Protocol = 112
	PROTO_PGM             Protocol = 113
	PROTO_L2TP            Protocol = 115
	PROTO_DDX             Protocol = 116
	PROTO_IATP            Protocol = 117
	PROTO_STP             Protocol = 118
	PROTO_SRP             Protocol = 119
	PROTO_UTI             Protocol = 120
	PROTO_SMP             Protocol = 121
	PROTO_SM              Protocol = 122
	PROTO_PTP             Protocol = 123
	PROTO_ISIS            Protocol = 124
	PROTO_FIRE            Protocol = 125
	PROTO_CRTP            Protocol = 126
	PROTO_CRUDP           Protocol = 127
	PROTO_SSCOPMCE        Protocol = 128
	PROTO_IPLT            Protocol = 129
	PROTO_SPS             Protocol = 130
	PROTO_PIPE            Protocol = 131
	PROTO_SCTP            Protocol = 132
	PROTO_FC              Protocol = 133
	PROTO_RSVP_E2E_IGNORE Protocol = 134
	PROTO_UDPLite         Protocol = 136
	PROTO_MPLS_in_IP      Protocol = 137
	PROTO_MANET           Protocol = 138
	PROTO_HIP             Protocol = 139
	PROTO_SHIM6           Protocol = 140
	PROTO_WESP            Protocol = 141
	PROTO_ROHC            Protocol = 142
	PROTO_ETHERNET        Protocol = 143
)