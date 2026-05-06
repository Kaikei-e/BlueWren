//! 受信メッセージの端末安全な表示への変換
//!
//! 受信した平文をそのまま `print!` すると、ANSI escape sequence や
//! OSC sequence を悪意ある peer が混入させてターミナルを操作できる。
//! 本モジュールは、表示前に制御文字を除去/可視化する。
//!
//! 方針:
//! - `\n`, `\r`, `\t` のみ許可
//! - その他の C0/C1 制御文字は U+FFFD (置換文字) に変換
//! - ESC (0x1B) で始まる CSI/OSC/その他のエスケープシーケンスを除去
//!
//! 詳細は監査 F-09 を参照。

use std::str::Chars;

/// 表示用に sanitize する
pub fn sanitize_for_terminal(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars();

    while let Some(c) = chars.next() {
        match c {
            // 改行・タブは保持
            '\n' | '\r' | '\t' => out.push(c),

            // ESC: エスケープシーケンス全体を読み飛ばす
            '\x1b' => {
                consume_escape_sequence(&mut chars);
            }

            // その他の制御文字は置換文字に変換
            c if c.is_control() => out.push('\u{FFFD}'),

            // 通常文字
            c => out.push(c),
        }
    }

    out
}

/// ESC を読んだ後、その後続のエスケープシーケンスを消費する
///
/// 簡略化された実装で、CSI (`ESC [ ... 終端文字`)、OSC (`ESC ] ... BEL/ST`)、
/// その他 1〜2 バイトのシーケンスを概ね捕捉する。完璧なパーサではないが、
/// 既知の悪用パターン (画面クリア、カーソル制御、クリップボード書き換え、
/// タイトル書き換え) を実用的に防げる。
fn consume_escape_sequence(chars: &mut Chars) {
    let next = match chars.next() {
        Some(c) => c,
        None => return,
    };

    match next {
        // CSI: ESC [ ... 終端 (0x40-0x7E)
        '[' => {
            for c in chars.by_ref() {
                if matches!(c, '\x40'..='\x7E') {
                    break;
                }
            }
        }
        // OSC: ESC ] ... BEL or ESC \
        ']' => {
            let mut prev = '\0';
            for c in chars.by_ref() {
                if c == '\x07' || (prev == '\x1b' && c == '\\') {
                    break;
                }
                prev = c;
            }
        }
        // その他の単発エスケープ (例: ESC c, ESC =, ESC >)
        // 1 バイトで終わるので何もしない (= すでに consume 済み)
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_normal_text() {
        assert_eq!(sanitize_for_terminal("hello world"), "hello world");
    }

    #[test]
    fn keeps_newlines_and_tabs() {
        assert_eq!(sanitize_for_terminal("a\nb\tc"), "a\nb\tc");
    }

    #[test]
    fn replaces_other_control_chars() {
        let result = sanitize_for_terminal("a\x07b\x08c");
        assert_eq!(result, "a\u{FFFD}b\u{FFFD}c");
    }

    #[test]
    fn strips_csi_clear_screen() {
        // 画面クリアシーケンス \x1b[2J は除去される
        let result = sanitize_for_terminal("safe\x1b[2Jafter");
        assert_eq!(result, "safeafter");
    }

    #[test]
    fn strips_csi_cursor_move() {
        let result = sanitize_for_terminal("a\x1b[10;20Hb");
        assert_eq!(result, "ab");
    }

    #[test]
    fn strips_osc_clipboard_write() {
        // OSC 52 によるクリップボード書き込み試行を除去
        let result = sanitize_for_terminal("hi\x1b]52;c;ZXZpbA==\x07end");
        assert_eq!(result, "hiend");
    }

    #[test]
    fn strips_osc_terminated_by_st() {
        // OSC が ESC \ (ST) で終わるパターン
        let result = sanitize_for_terminal("a\x1b]0;TITLE\x1b\\b");
        assert_eq!(result, "ab");
    }

    #[test]
    fn handles_lone_escape() {
        // ESC のみで他に続かない場合も安全
        let result = sanitize_for_terminal("a\x1bb");
        // ESC の直後の 'b' が単発エスケープとして消費される
        assert_eq!(result, "a");
    }

    #[test]
    fn preserves_unicode_text() {
        // 日本語などの Unicode 文字は通常表示できる
        assert_eq!(sanitize_for_terminal("こんにちは"), "こんにちは");
        assert_eq!(sanitize_for_terminal("emoji 😊"), "emoji 😊");
    }
}
