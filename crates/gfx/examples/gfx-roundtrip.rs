use gfx::prelude::*;
use std::io::{Read, Write};

fn main() {
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .expect("read stdin");
    let mut parser = Parser::new(ParseOptions::default());
    parser.feed(&input);
    let mut writer = Writer::new();
    while let Some(ev) = parser.next_event().expect("parse") {
        if let Event::Blob { data, .. } = &ev {
            eprintln!("blob parsed len={}", data.len());
        }
        writer.write(&ev).expect("write");
    }
    let mut tail = Vec::new();
    parser.finish(&mut tail).expect("finish");
    for ev in tail {
        writer.write(&ev).expect("write");
    }
    std::io::stdout()
        .write_all(writer.as_slice())
        .expect("write stdout");
}
