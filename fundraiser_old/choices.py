User_Type = (
    ("Admin", "Admin"),
    ("Backend User", "Backend User"),
    ("End User", "End User"),
)


Payment_Status = (
    ('created', 'created'),
    ('captured', 'captured'),
    ('failed', 'failed'),
    ('refund', 'refund'),
)

sensitivity_choices = (
    ('high sensitive', 'high sensitive'),
    ('moderate', 'moderate'),
    ('charity', 'charity'),
)

generic_emails_departments = (
    ('Defence', 'Defence'),
    ('Home Affairs', 'Home Affairs'),
    ('Chemicals', 'Chemicals'),
)

generic_emails_role = (
    ('Minister of Defence', 'Minister of Defence'),
    ('Minister of Home Affairs', 'Minister of Home Affairs'),
    ('Minister of Chemicals', 'Minister of Chemicals'),
)

Withdrawal_Status = (
    ('New', 'New'),
    ('Approved', 'Approved'),
    ('Decline', 'Decline'),
)


Refund_Status = (
    ('not requested', 'not requested'),
    ('request refund', 'request refund'),
    ('refund approved', 'refund approved'),
    ('refund decline', 'refund decline'),
)