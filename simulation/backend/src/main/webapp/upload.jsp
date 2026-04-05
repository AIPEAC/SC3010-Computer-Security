<%--
  VULNERABLE CODE
  File: src/main/webapp/upload.jsp
  Purpose: Simple HTML file-upload form. Sends a multipart/form-data POST to
           /upload.action. The form itself is benign — the vulnerability lies in how
           Struts2 2.3.28 processes the Content-Type header of any multipart request,
           which an attacker can craft externally without using this form at all.
  Time in attack timeline: UI surface available from server deployment. Attackers
                            bypass this form entirely and POST directly to /upload.action.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>File Upload — Demo</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 60px auto; max-width: 500px; }
    h2   { color: #333; }
    input[type=file]   { margin: 12px 0; display: block; }
    input[type=submit] { padding: 8px 20px; background: #0078d4; color: #fff;
                         border: none; cursor: pointer; border-radius: 4px; }
  </style>
</head>
<body>
  <h2>Upload a File</h2>
  <form action="upload.action" method="post" enctype="multipart/form-data">
    <label for="upload">Choose file:</label>
    <input type="file" id="upload" name="upload" />
    <input type="submit" value="Upload" />
  </form>
</body>
</html>
