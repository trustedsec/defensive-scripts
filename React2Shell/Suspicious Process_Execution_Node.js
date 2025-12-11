title: Suspicious Command Execution from Node.js Process
id: b2c3d4e5-f6a7-4b5c-9d0e-1f2a3b4c5d6e
status: experimental
description: Detects execution of reconnaissance or system commands spawned by Node.js processes, indicating potential React2Shell exploitation
references:
    - https://www.wiz.io/blog/nextjs-cve-2025-55182-react2shell-deep-dive
author: TrustedSec
date: 2025/12/10
tags:
    - attack.execution
    - attack.t1059
    - attack.discovery
    - attack.t1082
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentImage|endswith:
            - '/node'
            - '/nodejs'
    selection_commands:
        Image|endswith:
            - '/whoami'
            - '/id'
            - '/uname'
            - '/hostname'
            - '/cat'
            - '/curl'
            - '/wget'
            - '/nc'
            - '/ncat'
            - '/bash'
            - '/sh'
    condition: selection_parent and selection_commands
falsepositives:
    - Legitimate build processes or scripts executed by Node.js
    - Development and testing environments (tune based on your environment)
level: high
