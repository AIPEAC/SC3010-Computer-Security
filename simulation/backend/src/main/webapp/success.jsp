<%--
  VULNERABLE CODE
  File: src/main/webapp/success.jsp
  Purpose: Confirmation page shown after a legitimate file upload succeeds.
           Displayed only when the Struts2 action returns SUCCESS and the request
           was NOT exploited (i.e., the Content-Type was a normal multipart value).
  Time in attack timeline: Shown to normal users at any time. When CVE-2017-5638
                            is exploited the attacker never sees this page — execution
                            happens at the parser level and the response varies.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Upload Successful</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 60px auto; max-width: 500px; }
    h2   { color: #2e7d32; }
    a    { color: #0078d4; }
  </style>
</head>
<body>
  <h2>Upload Successful</h2>
  <p>Your file was received and stored.</p>
  <p><a href="upload.jsp">Upload another file</a></p>
</body>
</html>
