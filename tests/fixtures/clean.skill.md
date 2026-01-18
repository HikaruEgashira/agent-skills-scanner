# Clean Skill

A legitimate skill file with no security issues.

## Description

This skill helps users format their code according to best practices.

## Instructions

When the user asks for code formatting:
1. Identify the programming language
2. Apply the appropriate style guide
3. Return the formatted code

## Usage

```bash
# Format a JavaScript file
skill format --file app.js

# Format with custom config
skill format --config .prettierrc
```

## Configuration

The skill reads configuration from a local config file.

## Examples

### Input
```javascript
function hello(){console.log("world")}
```

### Output
```javascript
function hello() {
  console.log("world");
}
```

## Support

For issues, please open a GitHub issue.
