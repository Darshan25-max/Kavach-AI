import re
from typing import Optional


# Language detection patterns based on file extensions and syntax
LANGUAGE_PATTERNS = {
    "python": {
        "extensions": [".py"],
        "keywords": ["def ", "import ", "from ", "class ", "if __name__", "print(", "self.", "elif ", "#!/usr/bin/env python"],
        "weight": 1.0,
    },
    "javascript": {
        "extensions": [".js", ".jsx", ".mjs"],
        "keywords": ["const ", "let ", "var ", "function ", "=>", "console.log(", "require(", "module.exports", "document."],
        "weight": 1.0,
    },
    "typescript": {
        "extensions": [".ts", ".tsx"],
        "keywords": [": string", ": number", ": boolean", "interface ", "type ", ": void", "as ", "enum "],
        "weight": 1.0,
    },
    "java": {
        "extensions": [".java"],
        "keywords": ["public class", "private ", "protected ", "System.out.println", "import java.", "@Override", "public static void main"],
        "weight": 1.0,
    },
    "php": {
        "extensions": [".php"],
        "keywords": ["<?php", "$_", "->", "echo ", "function ", "namespace ", "use "],
        "weight": 1.0,
    },
    "ruby": {
        "extensions": [".rb"],
        "keywords": ["def ", "end", "puts ", "require ", "class ", "attr_accessor", "do |", ".each do"],
        "weight": 1.0,
    },
    "go": {
        "extensions": [".go"],
        "keywords": ["func ", "package ", "import (", "fmt.Print", ":= ", "go func", "chan "],
        "weight": 1.0,
    },
    "rust": {
        "extensions": [".rs"],
        "keywords": ["fn ", "let mut", "impl ", "pub fn", "use std::", "println!(", "unsafe "],
        "weight": 1.0,
    },
    "csharp": {
        "extensions": [".cs"],
        "keywords": ["using System", "namespace ", "public class", "Console.WriteLine", "private void", "var "],
        "weight": 1.0,
    },
    "c": {
        "extensions": [".c", ".h"],
        "keywords": ["#include <", "int main(", "printf(", "malloc(", "free(", "void *"],
        "weight": 1.0,
    },
    "cpp": {
        "extensions": [".cpp", ".cc", ".hpp"],
        "keywords": ["#include <", "std::", "cout <<", "class ", "template <", "namespace "],
        "weight": 1.0,
    },
    "sql": {
        "extensions": [".sql"],
        "keywords": ["SELECT ", "INSERT INTO", "UPDATE ", "DELETE FROM", "CREATE TABLE", "ALTER TABLE", "DROP TABLE"],
        "weight": 1.0,
    },
    "html": {
        "extensions": [".html", ".htm"],
        "keywords": ["<!DOCTYPE", "<html", "<head>", "<body>", "<div", "<script"],
        "weight": 1.0,
    },
    "css": {
        "extensions": [".css", ".scss"],
        "keywords": ["{", "}", "color:", "margin:", "padding:", "display:", "position:"],
        "weight": 0.5,
    },
}


def detect_language(code: str) -> str:
    """Detect the programming language of the given code snippet."""
    scores = {}

    for lang, patterns in LANGUAGE_PATTERNS.items():
        score = 0
        for keyword in patterns["keywords"]:
            count = len(re.findall(re.escape(keyword), code, re.IGNORECASE))
            score += count * patterns["weight"]
        scores[lang] = score

    if not scores or max(scores.values()) == 0:
        return "unknown"

    return max(scores, key=scores.get)


def extract_code_snippet(code: str, line_number: int, context_lines: int = 3) -> str:
    """Extract a code snippet around a given line number."""
    lines = code.split("\n")
    start = max(0, line_number - context_lines - 1)
    end = min(len(lines), line_number + context_lines)
    snippet_lines = lines[start:end]
    return "\n".join(f"{i+1}: {line}" for i, line in enumerate(snippet_lines, start=start))


def count_lines(code: str) -> int:
    """Count non-empty lines of code."""
    return len([line for line in code.split("\n") if line.strip()])


def get_language_for_extension(extension: str) -> Optional[str]:
    """Get the language name for a file extension."""
    ext = extension.lower()
    if not ext.startswith("."):
        ext = "." + ext
    for lang, patterns in LANGUAGE_PATTERNS.items():
        if ext in patterns["extensions"]:
            return lang
    return None


def get_supported_languages() -> list[str]:
    """Get list of all supported languages."""
    return list(LANGUAGE_PATTERNS.keys())
