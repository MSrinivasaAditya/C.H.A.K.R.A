from core.llm_client import LocalLLMClient
cli = LocalLLMClient()
code = """// VULNERABLE: String concatenation
String username = request.getParameter("username");
String query = "SELECT secret FROM Users WHERE username = '" + username + "'";
Statement statement = connection.createStatement();
ResultSet result = statement.executeQuery(query);
"""
prompt = f"You are a professional security auditor. Review the following code snippet for vulnerabilities related to the skill: 'SQL Injection'.\nSkill Description: Detect SQL Injection.\nAnalyze the code closely. If you find any issue, explain the vulnerability starting with the word 'Vulnerability'. If the code is completely safe, simply respond with 'Safe'.\n\nCode:\n{code}"
resp = cli.generate(prompt)
print(repr(resp))
