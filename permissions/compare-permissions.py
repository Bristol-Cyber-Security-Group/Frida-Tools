
import sys

package = sys.argv[1]

# Read content from granted-perms.txt
with open(f'logs/{package}/granted-perms.txt', 'r') as f:
    granted_perms = set(f.readlines())

# Read content from requested-perms.txt
with open(f'logs/{package}/requested-perms.txt', 'r') as f:
    requested_perms = set(f.readlines())

# Find differences
only_requested = requested_perms - granted_perms
only_granted = granted_perms - requested_perms

# Write to summary.txt
with open(f'logs/{package}/summary.txt', 'w') as f:
    f.write("Only requested, not granted:\n")
    for perm in only_requested:
        f.write(perm)
    
    f.write("\nOnly granted, not requested:\n")
    for perm in only_granted:
        f.write(perm)
