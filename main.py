"""Command-line interface for PassVault CLI."""

import argparse
import getpass
import sys
from pathlib import Path
from src.crypto import generate_secure_password, evaluate_password_strength
from src.vault import AuthenticationError, Vault, VaultError


def print_banner():
    banner = """
===================================================================
     PASS VAULT CLI - AES-256-GCM Authenticated Secret Manager     
===================================================================
    """
    print(banner)


def get_vault(db_path: str = "vault.db") -> Vault:
    return Vault(db_path=db_path)


def prompt_master_password(confirm: bool = False) -> str:
    pwd = getpass.getpass("Enter master password: ")
    if not pwd:
        print("Error: Master password cannot be blank.")
        sys.exit(1)
    if confirm:
        pwd2 = getpass.getpass("Confirm master password: ")
        if pwd != pwd2:
            print("Error: Passwords do not match.")
            sys.exit(1)
    return pwd


def cmd_init(args):
    vault = get_vault(args.db)
    if vault.is_initialized():
        print(f"[*] Vault '{args.db}' is already initialized.")
        return

    print(f"[*] Initializing new cryptographic vault: {args.db}")
    pwd = prompt_master_password(confirm=True)
    vault.initialize(pwd)
    print("[+] Master password set successfully! Vault encrypted with AES-256-GCM.")


def cmd_add(args):
    vault = get_vault(args.db)
    pwd = prompt_master_password()
    try:
        key = vault.unlock(pwd)
    except AuthenticationError as e:
        print(f"[!] {e}")
        sys.exit(1)

    secret_pwd = args.password
    if args.generate:
        secret_pwd = generate_secure_password(length=args.length)
        print(f"[+] Generated strong random password: {secret_pwd}")
    elif not secret_pwd:
        secret_pwd = getpass.getpass("Enter secret password: ")

    vault.add_secret(
        key=key,
        service=args.service,
        username=args.user,
        password=secret_pwd,
        notes=args.notes or "",
    )
    print(f"[+] Saved secret for '{args.service}' ({args.user}) into vault.")


def cmd_get(args):
    vault = get_vault(args.db)
    pwd = prompt_master_password()
    try:
        key = vault.unlock(pwd)
    except AuthenticationError as e:
        print(f"[!] {e}")
        sys.exit(1)

    entry = vault.get_secret(key, args.service, args.user)
    if not entry:
        print(f"[!] No credential found for service '{args.service}'.")
        return

    print("\n--- Decrypted Secret Entry ---")
    print(f"Service:     {entry['service']}")
    print(f"Username:    {entry['username']}")
    print(f"Password:    {entry['password']}")
    if entry['notes']:
        print(f"Notes:       {entry['notes']}")
    print(f"Last Update: {entry['updated_at']}")
    print("-" * 30 + "\n")


def cmd_list(args):
    vault = get_vault(args.db)
    entries = vault.list_secrets()

    print(f"\n--- Stored Credentials in {args.db} ---")
    print(f"{'ID':<4} | {'SERVICE':<25} | {'USERNAME':<25} | {'LAST UPDATED'}")
    print("-" * 75)
    if not entries:
        print("  Vault is empty.")
    else:
        for e in entries:
            print(f"{e['id']:<4} | {e['service']:<25} | {e['username']:<25} | {e['updated_at']}")
    print("-" * 75 + "\n")


def cmd_audit(args):
    vault = get_vault(args.db)
    pwd = prompt_master_password()
    try:
        key = vault.unlock(pwd)
    except AuthenticationError as e:
        print(f"[!] {e}")
        sys.exit(1)

    report = vault.audit_passwords(key)
    print("\n" + "=" * 60)
    print("               VAULT SECURITY HEALTH AUDIT REPORT          ")
    print("=" * 60)
    print(f"Total Stored Credentials:  {report['total_secrets']}")
    print(f"Weak Passwords Flagged:    {report['weak_passwords']}")
    print(f"Reused Password Groups:    {report['reused_passwords_count']}")

    if report["reused_groups"]:
        print("\n[!] WARNING: Reused Passwords Detected:")
        for group in report["reused_groups"]:
            print(f"  - Reused across: {', '.join(group)}")

    print("\n--- Credential Breakdown ---")
    for item in report["entries"]:
        badge = f"[{item['strength']}]"
        print(f"  {item['service']:<20} ({item['username']}): {badge:<14} (Entropy: {item['entropy_bits']} bits)")
    print("=" * 60 + "\n")


def cmd_generate(args):
    pwd = generate_secure_password(length=args.length, include_symbols=not args.no_symbols)
    eval_res = evaluate_password_strength(pwd)

    print("\n--- Generated Cryptographic Password ---")
    print(f"Password:     {pwd}")
    print(f"Length:       {eval_res['length']} characters")
    print(f"Entropy:      {eval_res['entropy_bits']} bits ({eval_res['strength']})")
    print("-" * 40 + "\n")


def cmd_demo(args):
    demo_db = Path("demo_vault.db")
    if demo_db.exists():
        demo_db.unlink()

    print("[*] Running automated end-to-end PassVault demonstration...")
    vault = Vault(demo_db)
    master_pass = "PiyushSuperSecretMaster2026!"

    print("\n1. Initializing vault with master key...")
    key = vault.initialize(master_pass)
    print("[PASS] Master key derived with PBKDF2 (600,000 iterations).")

    print("\n2. Encrypting credentials with AES-256-GCM...")
    vault.add_secret(key, "github.com", "piyush1008-cyber", "ghp_MockToken98273491823749817234", "Personal API token")
    vault.add_secret(key, "aws-console", "piyush-admin", "AKIAIOSFODNN7EXAMPLE_SECRET!", "Production root")
    vault.add_secret(key, "legacy-forum", "piyush123", "password123", "Old insecure forum")
    print("[PASS] 3 accounts securely encrypted & stored.")

    print("\n3. Decrypting 'github.com' credential...")
    secret = vault.get_secret(key, "github.com")
    print(f"[PASS] Retrieved: {secret['service']} | {secret['username']} | {secret['password'][:10]}...")

    print("\n4. Running Security Health Audit...")
    report = vault.audit_passwords(key)
    print(f"[PASS] Total: {report['total_secrets']}, Weak flagged: {report['weak_passwords']}")
    for e in report['entries']:
        print(f"  - {e['service']:<15}: [{e['strength']}] ({e['entropy_bits']} bits entropy)")

    print("\n[+] PassVault CLI demonstration complete!")


def main():
    print_banner()
    parser = argparse.ArgumentParser(description="PassVault CLI - AES-256-GCM Authenticated Secret Manager")
    parser.add_argument("--db", default="vault.db", help="Path to database (default: vault.db)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # init
    p_init = subparsers.add_parser("init", help="Initialize master password for the vault")
    p_init.set_defaults(func=cmd_init)

    # add
    p_add = subparsers.add_parser("add", help="Store a credential")
    p_add.add_argument("service", help="Service or domain (e.g. github.com)")
    p_add.add_argument("--user", required=True, help="Username or email")
    p_add.add_argument("--password", help="Secret password (prompts if omitted)")
    p_add.add_argument("--generate", action="store_true", help="Auto-generate a strong password")
    p_add.add_argument("--length", type=int, default=20, help="Generated password length (default: 20)")
    p_add.add_argument("--notes", help="Optional notes")
    p_add.set_defaults(func=cmd_add)

    # get
    p_get = subparsers.add_parser("get", help="Retrieve and decrypt a credential")
    p_get.add_argument("service", help="Service or domain")
    p_get.add_argument("--user", help="Username if multiple accounts exist")
    p_get.set_defaults(func=cmd_get)

    # list
    p_list = subparsers.add_parser("list", help="List all accounts (metadata only)")
    p_list.set_defaults(func=cmd_list)

    # audit
    p_audit = subparsers.add_parser("audit", help="Audit vault for weak and reused passwords")
    p_audit.set_defaults(func=cmd_audit)

    # generate
    p_gen = subparsers.add_parser("generate", help="Generate a cryptographically strong password")
    p_gen.add_argument("--length", type=int, default=20, help="Password length (default: 20)")
    p_gen.add_argument("--no-symbols", action="store_true", help="Exclude symbols")
    p_gen.set_defaults(func=cmd_generate)

    # demo
    p_demo = subparsers.add_parser("demo", help="Run automated demonstration")
    p_demo.set_defaults(func=cmd_demo)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
