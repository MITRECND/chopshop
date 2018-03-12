# Copyright (c) 2014 The MITRE Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

import smtplib
import email.MIMEText
 
def send_alert(addresses, alert, server, msg_from=None):
    """Given a comma-separated string of e-mail addresses,
    an alert string, and an outgoing SMTP server,
    send an e-mail to those addresses stating that the
    backdoor is active. Optionally, provide an
    address stating from whom the e-mail originates.
    """
    if not msg_from:
        msg_from = "alert@organization.domain"

    msg = email.MIMEText.MIMEText("ALERT: %s is active" % alert)
    msg["Subject"] = "Status: Alert"
    msg["From"] = msg_from
    msg["To"] = addresses

    address_list = []
    for a in addresses.split(","):
        address_list.append(a)

    s = smtplib.SMTP(server)
    s.sendmail(msg_from, address_list, msg.as_string())
    s.quit()
