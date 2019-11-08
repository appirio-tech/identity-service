subject:Topcoder account activation
<html>
<head>
<style type="text/css">
p {
  display: block;
  -webkit-margin-before: 1em;
  -webkit-margin-after: 1em;
  -webkit-margin-start: 0px;
  -webkit-margin-end: 0px;
  margin: 1em 0 1em 0;
}
</style>
</head>
<body>
<p>
Hi ${user.handle},
</p>

<p>
Thanks for joining Topcoder! Please confirm your email address and activate your account by clicking this link:
</p>

<p>
<a href="${env.apiUrlBase}/pub/activation.html?code=${user.credential.activationCode}&retUrl=${redirectUrl}">${env.apiUrlBase}/pub/activation.html?code=${user.credential.activationCode}&retUrl=${redirectUrl}</a>
</p>

<p>
If you have any trouble with your account, you can always email us at <a href="mailto:support@topcoder.com">support@topcoder.com</a>.
</p>

<p>
Regards,<br />
The Topcoder team
</p>

<p>
If you didn't register for Topcoder, please ignore this message.
</p>

</body>
</html>

