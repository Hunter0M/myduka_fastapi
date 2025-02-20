# def get_password_reset_template(reset_link: str) -> str:
#     return f"""
#     <div style="max-width: 600px; margin: 0 auto; padding: 20px; font-family: Arial, sans-serif; background-color: #f8fafc;">
#         <div style="background-color: white; border-radius: 8px; padding: 24px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
#             <h2 style="color: #1e3a8a; font-size: 24px; font-weight: 600; margin-bottom: 20px; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px;">
#                 Password Reset Request
#             </h2>
            
#             <div style="margin-bottom: 24px; color: #1e293b; line-height: 1.6;">
#                 <p>We received a request to reset your password. If you didn't make this request, you can ignore this email.</p>
#                 <p>To reset your password, click the button below:</p>
#             </div>
            
#             <div style="text-align: center; margin: 32px 0;">
#                 <a href="{reset_link}" 
#                    style="background-color: #2563eb; color: white; padding: 12px 24px; 
#                           border-radius: 6px; text-decoration: none; font-weight: 600;
#                           display: inline-block;">
#                     Reset Password
#                 </a>
#             </div>
            
#             <div style="margin-top: 24px; color: #64748b; font-size: 14px;">
#                 <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
#                 <p style="word-break: break-all; color: #2563eb;">{reset_link}</p>
#                 <p>This link will expire in 30 minutes for security reasons.</p>
#             </div>
            
#             <div style="margin-top: 24px; padding-top: 20px; border-top: 1px solid #e2e8f0; 
#                         font-size: 14px; color: #64748b; text-align: center;">
#                 If you didn't request a password reset, please ignore this email or contact support
#                 if you have concerns about your account security.
#             </div>
#         </div>
#     </div>
#     """ 