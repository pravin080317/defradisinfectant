#PowerShell script using Power Platform CLI (PAC CLI) that:
#Loops through all security roles in a Power Platform environment.
#Extracts table (entity) permissions for each role.
#Exports the data to a CSV file for further analysis.
# Define the output CSV file
$outputFile = "SecurityRoles_Permissions.csv"

# Initialize CSV with headers
@"
SecurityRole, TableName, Read, Write, Create, Delete, Append, AppendTo, Assign, Share
"@ | Out-File -Encoding utf8 $outputFile

# Get all security roles in the environment
$securityRoles = pac dataverse list security-roles --output json | ConvertFrom-Json

# Loop through each security role and extract table permissions
foreach ($role in $securityRoles) {
    $roleName = $role.name
    $roleId = $role.roleid

    # Get role privileges (permissions for tables)
    $rolePrivileges = pac dataverse list security-role-privileges --name "$roleName" --output json | ConvertFrom-Json

    foreach ($privilege in $rolePrivileges) {
        $tableName = $privilege.entityname
        $read = if ($privilege.privilegeMask -band 1) { "Yes" } else { "No" }
        $write = if ($privilege.privilegeMask -band 2) { "Yes" } else { "No" }
        $create = if ($privilege.privilegeMask -band 4) { "Yes" } else { "No" }
        $delete = if ($privilege.privilegeMask -band 8) { "Yes" } else { "No" }
        $append = if ($privilege.privilegeMask -band 16) { "Yes" } else { "No" }
        $appendTo = if ($privilege.privilegeMask -band 32) { "Yes" } else { "No" }
        $assign = if ($privilege.privilegeMask -band 64) { "Yes" } else { "No" }
        $share = if ($privilege.privilegeMask -band 128) { "Yes" } else { "No" }

        # Append to CSV
        "$roleName, $tableName, $read, $write, $create, $delete, $append, $appendTo, $assign, $share" | Out-File -Append -Encoding utf8 $outputFile
    }
}

Write-Host "Security Roles and Table Permissions exported to: $outputFile"
