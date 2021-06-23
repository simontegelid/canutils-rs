use hex::FromHex;
use nom::character::complete::{alphanumeric1, digit1, hex_digit1, space0};

#[cfg(test)]
mod tests {
    use crate::candump_parser::*;

    #[test]
    fn it_works() {
        let exp = LogEntry {
            timestamp: Timestamp {
                seconds: 1547046014,
                micros: 597158,
            },
            interface: "vcan0".to_string(),
            frame: CanFrame {
                can_id: 123,
                data: vec![1, 199],
                is_fd: false,
                fd_flags: 0,
            },
        };
        assert_eq!(
            dump_entry("(1547046014.597158) vcan0 7B#01C7"),
            Ok(("", exp))
        );
    }

    #[test]
    fn it_fd_works() {
        let exp = LogEntry {
            timestamp: Timestamp {
                seconds: 1547046014,
                micros: 597158,
            },
            interface: "vcan0".to_string(),
            frame: CanFrame {
                can_id: 123,
                data: vec![1, 199],
                is_fd: true,
                fd_flags: 1,
            },
        };
        assert_eq!(
            dump_entry("(1547046014.597158) vcan0 7B##101C7"),
            Ok(("", exp))
        );
    }

    #[test]
    fn it_fd_works2() {
        let exp = LogEntry {
            timestamp: Timestamp {
                seconds: 1547046014,
                micros: 597158,
            },
            interface: "vcan0".to_string(),
            frame: CanFrame {
                can_id: 123,
                data: vec![1, 199],
                is_fd: true,
                fd_flags: 3,
            },
        };
        assert_eq!(
            dump_entry("(1547046014.597158) vcan0 7B##301C7"),
            Ok(("", exp))
        );
    }
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Timestamp {
    pub seconds: u64,
    pub micros: u64,
}

named!(timestamp<&str, Timestamp>,
    do_parse!(
                 tag!("(")                             >>
        seconds: map_res!(digit1, |d: &str| d.parse()) >>
                 tag!(".")                             >>
        micros:  map_res!(digit1, |d: &str| d.parse()) >>
                 tag!(")")                             >>
        (Timestamp { seconds, micros })
    )
);

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CanFrame {
    pub can_id: u32,
    pub data: Vec<u8>,
    pub is_fd: bool,
    pub fd_flags: u8,
}

named!(frame<&str, CanFrame>,
    do_parse!(
        can_id: map_res!(hex_digit1, |d| u32::from_str_radix(d, 16))  >>
        is_fd: alt!(
            tag!("##") => {|_|true} |
            tag!("#") => {|_|false}
        )                                                             >>
        fd_flags: switch!(call!(|i| Ok((i, is_fd))),
            true => map_res!(take!(1), |d| u8::from_str_radix(d, 16)) |
            false => value!(0)
        )                                                             >>
        data:   map_res!(hex_digit1, |d: &str| -> Result<Vec<u8>, _> {
                    Vec::from_hex(d)
                })                                                    >>
        (CanFrame { can_id, data, is_fd, fd_flags })
    )
);

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LogEntry {
    timestamp: Timestamp,
    interface: String,
    frame: CanFrame,
}

impl LogEntry {
    pub fn timestamp(&self) -> &Timestamp {
        &self.timestamp
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }

    pub fn frame(&self) -> &CanFrame {
        &self.frame
    }
}

named!(pub dump_entry<&str, LogEntry>,
    do_parse!(
        timestamp:     timestamp     >>
                       space0        >>
        interface:     alphanumeric1 >>
                       space0        >>
        frame:         frame         >>
        (LogEntry { timestamp, interface: interface.to_string(), frame })
    )
);
