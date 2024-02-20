start cmd.exe @cmd /k "d:&cd D:\USER\Downloads\ATLAS\Projects\ERC-1404 Testing\security-token-testing&yarn chain"
sleep 10
start cmd.exe @cmd /k "d:&cd D:\USER\Downloads\ATLAS\Projects\ERC-1404 Testing\security-token-testing&yarn start"
start cmd.exe @cmd /k "d:&cd D:\USER\Downloads\ATLAS\Projects\ERC-1404 Testing\security-token-testing&yarn deploy --reset"