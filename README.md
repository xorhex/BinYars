![image](./pictures/Y_%20SymbolwithShuriken.png)

## Description

BinYars is a Binary Ninja Plugin which intergrates YARA-X into Binary Ninja - 2 of my favorate tools.

## Installation

This plugin comes in 2 parts.

**Rust Component**

This handles all of the Yara-X scanning and the Binary Ninja folder sorting and compilation of the Yara-X rules.

Steps:

- Clone repo

- In the root of  the repo, run `cargo build --release`

- Copy (or better yet symlink) the `libbinyars.[so|dll|dyno]` file to the Binary Ninja plugin dir.  On linux this is under: `~/.binaryninja/plugins/`

**Python Component**

This is all of the code for the Sidebar Widget as it's easier to write Qt Widgets in Python versus Rust (didn't even try).  It will make calls to the rust component to do scanning and other YARA-X things.

Steps:

- Copy the folder (or better yet symlink) `binyars-sidewidgit` to the Binary Ninja plugin dir.

**Post Installation**

Set directory the plugin will use to find the .yar files in.

### Settings

![](./pictures/BinYars-Settings.png)

## Features

**Project Level**

These are all found in the right click menu in the project view.

- Brew (Compile)
  
  - Compiles all of the rules found in the `Yara-X Directory`

- Oracle of Order (Scan + Sort)
  
  - **WARNING**: *This will reorganize the Binary Ninja Project folder structure and files, proceed with caution!*
  
  - Runs all of the compiled rules against all of the files in a project and then sorts them into folders based upon the metadata in the rule. Also makes the scan data available in the file's project description.
  
  - Recommend enabling `Delete Empty Project Folders` when using this feature.
  
  - Will save the scan results to the Binary Ninja's project metadata.
  
  - https://github.com/user-attachments/assets/ca187cd6-f121-4b7c-902b-e593ec9942a5

- Scanning Sage (Scan Only)
  
  - Runs all of the compiled rules against all of the files in the project. The results are avaliable in the description and can be viewed at the file level using the BinYars sidebar widget.

**File Level**

- Compile Rules
  
  - Compiles all of the rule found in the `Yara-X Directory`
    
    - Found under `Plugins` -> `BinYars` -> `Compile Rules`

- Sidebar Widget (defaults to the right side)
  
  - View scan results
    
    - ![](./pictures/BinYarsScanResultsSideWidget%20(Markup).png)
    
    - Can click through the string matches to where they are found in the binary
  
  - Scan the file
    
    - The Rescan button on the Scan Results tab will save the scan results to the bndb's metadata section.
  
  - Create / Edit / Format Yara-X rules
    
    - Comes with a crude, but mostly functioning editor.
    
    - ![](./pictures/BinYarsRuleEditor%20(Markup).png)

## Yara-X Rules

**Meta Section**

Add two fields to the meta section as needed.

- **bnfolder**: This is the folder name to assign all of the matches to in Binary Ninja's Project View

- **bndescription**: The rule description to render inside of Binary Ninja.  

**Console Module**

The plugin can surface console.[log|hex] messages, but the strings must match this format for them to be picked up.

```
console.hex("BN|rule:<rule name>|<ValueName>: ", <value>)
```

All console messages are parsed as follows:

- Must start with `BN|`; will be ignored if not

- Must have a `rule:<rule name>`entry between a set of `|`
  
  - This is due to the fact that the callback for capturing Yara-X console messages does not pass in the rule name that triggered the console message.
  
  - This is needed to map the console message to the rule.

- `<ValueName>` can be anything provided it does not include `|` as the code splits on those characters.
  
  - The value name and the value are rendered in the UI.  To group mulitple console call values together in the BinYars sidebar widget, use `.` to bind them  together.
    
    - For example, to render a both offset and size under Shellcode in the UI do this:
      
      - `("BN|rule:my_shellcode_rule|Shellcode.Offset: ", shellcode_offset)`
      
      - `("BN|rule:my_shellcode_rule|Shellcode.Size: ", shellcode_size)`
      
      - Both of these values will be combined into 1 entry in the sidebar widget under Shellcode
  
  - The value name **Offset** is special. When used, it will make the entry in the sidebar widget interactive; so when clicked upon, it will goto that location in the binary.

**Example Rule**

```
import "pe"
import "console"

rule this_rule_has_been_taken {
    meta:
        bnfolder = "Secret Sauce"
        bndescription = "This rule captures a very particular set of bytes, bytes I have acquired over a very long career. Bytes that make me a nightmare for binaries like you."
    strings:
        $very_particular_set_of_bytes = { ?? ?? ?? ?? ?? ?? ?? }
    condition:
        pe.is_pe and
        with
            offset = uint32(@very_particular_set_of_bytes[#very_particular_set_of_bytes] + 1),
            size = uint16(@very_particular_set_of_bytes[#very_particular_set_of_bytes] + !very_particular_set_of_bytes) : (
                console.hex("BN|rule:this_rule_has_been_taken|Taken.Offset: ", offset)
                and console.hex("BN|rule:this_rule_has_been_taken|Taken.Size: ", size)
        )
}
```

## TODOs

- Determine if the current view is part of a project, if so - do not register (or maybe just invalidate it) the Compile Rules plugin option.  This command is needed for instances of Binary Ninja that do not support projects.  
  
  - So for now there are 2 commands that do the same  thing: 
    
    - Brew (Compile)
    
    - Compile Rules

## Disclaimers

In order to complete this in a timely fashion amoungst other things in life, *vide coding* was used for significate portions of this plugin. I mean, who wants to hand craft Python Qt widgets or is maybe a Rust n00b. O' and [MIT License](./LICENSE)
