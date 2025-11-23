use thiserror::Error;
#[derive(Debug, Error)]
#[error("Invalid link type: {0}")]
pub struct InvalidLinkType(pub u16);
macro_rules! link_type {
    (
        $(
            $name:ident = $value:literal
        ),*
    ) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(u16)]
        pub enum LinkType {
            $(
                $name = $value,
            )*
        }

        impl TryFrom<u16> for LinkType {
            type Error = InvalidLinkType;

            fn try_from(value: u16) -> Result<Self, Self::Error> {
                match value {
                    $(
                        $value => Ok(LinkType::$name),
                    )*
                    _ => Err(InvalidLinkType(value)),
                }
            }
        }
        impl TryFrom<u32> for LinkType {
            type Error = InvalidLinkType;

            fn try_from(value: u32) -> Result<Self, Self::Error> {
                match value {
                    $(
                        $value => Ok(LinkType::$name),
                    )*
                    _ => Err(InvalidLinkType(value as u16)),
                }
            }
        }
    };
}
link_type! {
    // Standard Link Types
    Null = 0,
    Ethernet = 1,
    Ax25 = 3,
    Ieee802_5 = 6,
    ArcnetBsd = 7,
    Slip = 8,
    Ppp = 9,
    Fddi = 10,

    // HDLC and PPP Variants
    PppHdlc = 50,
    PppEther = 51,
    CHdlc = 104,
    PppPppd = 166,
    PppWithDir = 204,
    CHdlcWithDir = 205,
    FrelayWithDir = 206,

    // ATM, FR, and Raw IP
    AtmRfc1483 = 100,
    Raw = 101,
    Frelay = 107,
    Mfr = 182,

    // Wireless and Bluetooth
    Ieee802_11 = 105,
    Ieee802_11Prism = 119,
    Ieee802_11Radiotap = 127,
    Ieee802_11Avs = 163,
    BluetoothHciH4 = 187,
    Ieee802_15_4Withfcs = 195,
    BluetoothHciH4WithPhdr = 201,
    Ieee802_15_4NonaskPhy = 215,
    Ieee802_15_4Nofcs = 230,
    BluetoothLeLl = 251,
    BluetoothLinuxMonitor = 254,
    BluetoothBredrBb = 255,
    BluetoothLeLlWithPhdr = 256,
    Ieee802_15_4Tap = 283,

    // Operating System Specific
    Loop = 108,
    LinuxSll = 113,
    Pflog = 117,
    ArcnetLinux = 129,
    LinuxIrda = 144,
    LinuxLapd = 177,
    UsbLinux = 189,
    UsbLinuxMmapped = 220,
    Ipnet = 226,
    CanSocketcan = 227,
    Nflog = 239,
    Netlink = 253,
    Pktap = 258,
    UsbDarwin = 266,
    Vsock = 271,
    LinuxSll2 = 276,

    // SS7 and Telecommunication
    Mtp2WithPhdr = 139,
    Mtp2 = 140,
    Mtp3 = 141,
    Sccp = 142,
    GprsLlc = 169,
    GpfT = 170,
    GpfF = 171,

    // Industrial & Embedded
    IpmbLinux = 209,
    RtacSerial = 250,
    ProfibusDl = 257,
    ZwaveR1R2 = 261,
    ZwaveR3 = 262,
    WattstopperDlm = 263,
    ZWaveSerial = 287,

    // Networking/Other
    Ltalk = 114,
    IpOverFc = 122,
    Sunatm = 123,
    AppleIpOverIeee1394 = 138,
    Docsis = 143,
    BacnetMsTp = 165,
    Sita = 196,
    Erf = 197,
    Ax25Kiss = 202,
    Lapd = 203,
    LapbWithDir = 207,
    Fc2 = 224,
    Fc2WithFrameDelims = 225,
    Ipv4 = 228,
    Ipv6 = 229,
    Dbus = 231,
    DvbCi = 235,
    Mux27010 = 236,
    Stanag5066DPdu = 237,
    Netanalyzer = 240,
    NetanalyzerTransparent = 241,
    Ipoib = 242,
    Mpeg2Ts = 243,
    Ng40 = 244,
    NfcLlcp = 245,
    Infiniband = 247,
    Sctp = 248,
    UsbPcap = 249,
    Ppi = 192,
    Epon = 259,
    IpmiHpm2 = 260,
    Iso14443 = 264,
    Rds = 265,
    Sdlc = 268,
    Loratap = 270,
    NordicBle = 272,
    Docsis31Xra31 = 273,
    EthernetMpacket = 274,
    DisplayportAux = 275,
    Openvizsla = 278,
    Ebhscr = 279,
    VppDispatch = 280,
    DsaTagBrcm = 281,
    DsaTagBrcmPrepend = 282,
    DsaTagDsa = 284,
    DsaTagEdsa = 285,
    Elee = 286,
    Usb2_0 = 288,
    AtscAlp = 289
}
