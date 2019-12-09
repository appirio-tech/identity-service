subject:Topcoder account password reset
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
Hi, ${user.handle},
</p>

<p>
We received a request to reset your password. If you made this request, please follow this link:
</p>

<p>
<a href="${env.appUrlBase}/reset-password/?token=${token}&handle=${user.handle}">${env.appUrlBase}/reset-password/?token=${token}&handle=${user.handle}</a>
</p>

<p>
The link will expire soon: at ${expiry}. To get a new one, visit <a href="${env.appUrlBase}/reset-password/">${env.appUrlBase}/reset-password/</a>
</p>

<p>
Regards,<br />
The Topcoder team
</p>

<p>
If you got this message in error, please ignore it (your password will not change). If you have any trouble with your account, you can always email us at <a href="mailto:support@topcoder.com">support@topcoder.com</a>.
</p>

</body>
</html>
