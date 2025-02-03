# Define roles and their permissions
ROLES = {
    "Admin": {
        "manage_users": True,
        "assign_roles": True,
        "configure_settings": True,
        "access_inventory": True,
        "generate_reports": True,
        "manage_inventory": True,
        "manage_permissions": True,
        "oversee_billing": True,
    },
    "Inventory Manager": {
        "add_inventory": True,
        "update_inventory": True,
        "organize_inventory": True,
        "track_reorder": True,
        "perform_audits": True,
    },
    "Sales Manager": {
        "view_orders": True,
        "track_sales": True,
        "handle_customers": True,
        "apply_discounts": True,
        "manage_invoices": True,
    },
    "Cashier": {
        "process_transactions": True,
        "view_inventory": True,
        "generate_receipts": True,
        "update_order_status": True,
    },
}

def check_permission(user_role, permission):
    return ROLES.get(user_role, {}).get(permission, False)