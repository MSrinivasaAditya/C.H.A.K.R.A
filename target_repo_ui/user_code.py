// VULNERABLE: String concatenation
String username = request.getParameter("username");
String query = "SELECT secret FROM Users WHERE username = '" + username + "'";
Statement statement = connection.createStatement();
ResultSet result = statement.executeQuery(query);
