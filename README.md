# HaveIBeenPwned Auth Node

An authentication decision node that checks the supplied password against the [Have I Been Pwned](https://haveibeenpwned.com/Passwords) database of passwords previously exposed in data breaches.

---

## Compatibility

This node is compatible with the following systems:

| Product                             | Compatible? |
|-------------------------------------|-------------|
| ForgeRock Identity Cloud            | Yes         |
| ForgeRock Access Management (self-managed) | Yes         |
| ForgeRock Identity Platform (self-managed) | Yes         |

---

## Inputs

This node requires the following inbound data:

| Description          | Attribute Name | Source        |
|----------------------|----------------|---------------|
| The password to check for breaches | `password`     | Shared state  |

---

## Dependencies

To use this node, you must have already set up Identity Cloud integration with Have I Been Pwned.

---

## Configuration

The configurable properties for this node are:

| Property         | Usage                                                                                   |
|------------------|-----------------------------------------------------------------------------------------|
| **User Agent**   | The User Agent for API requests                                                        |
| **API Key**      | The HIBP API key                                                                       |
| **Threshold**    | The maximum number of breaches where this password was compromised. Enter `0` to ensure the password does not match any recorded breaches. |

---

## Outputs

### Outcomes
- **Compromised**: Compromised password detected.
- **Not Compromised**: Password not compromised.
- **Error**: An error message is output to the shared state.

---

## Troubleshooting

If this node logs an error, review the log messages for the transaction to identify the reason for the exception.

---

## Journey

If a user is identified as compromised, the administrator can take one of the following actions:
- Deny access to the user.
- Prompt the user to reset their password.
- Implement other security measures as necessary.
