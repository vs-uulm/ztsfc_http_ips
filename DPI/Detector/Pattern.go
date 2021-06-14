package Detector

/*
This file represents the signatures for the Detector. Here the patterns and regular expressions are defined, which are
used by the Detector, to check if a request is malicious.
*/

// Patterns for Path Traversal
var patternPathTrav = [1]string{
	"../",
}

// Regular Expressions for SQL Injection
<<<<<<< HEAD
var regexSQLInject = [17]string{
	"('|[0-9]+)(\\s)+(--|;)", // PATTERN CHANGED FROM ORIGINALLY:  "('|[0-9]+)(\\s)*(--|;)"
	"'\\s*or\\s+.+\\s*=\\s*.+\\s*(--|;)",
	"[0-9]+\\s*or\\s+.+\\s*=\\s*.+",
=======
var regexSQLInject = [16]string{
	"'\\s*or\\s+[a-z0-9]+\\s*=\\s*[a-z0-9]+\\s*(--|;)",
	"[0-9]+\\s*or\\s+[a-z0-9]+\\s*=\\s*[a-z0-9]+",
>>>>>>> 2922670d9695710464ab38dba8e2a701e23b768b
	"'\\s*union(\\s+all)?\\s+select[ a-z0-9'\"\\*,_\\(\\)\\-]+from[ a-z0-9\\-_\\(\\)\\-]+(--|;)",
	"[0-9]+\\s+union(\\s+all)?\\s+select[ a-z0-9'\"\\*,_\\(\\)\\-]+from[ a-z0-9\\-_\\(\\)\\-]+",
	";\\s*select[ a-z0-9'\"\\*,_\\(\\)\\-]+from[ a-z0-9\\-_\\(\\)\\-]+(--|;)",
	";\\s*insert\\s+into\\s+[ a-z0-9\\-_\\(\\)\\-].*\\s+values\\s*\\(([ a-z0-9'\"\\*,_\\(\\)\\-]+\\s*,\\s*)*[ a-z0-9'\"\\*_\\(\\)\\-]+\\)\\s*(--|;)",
	";\\s*insert\\s+into\\s+[ a-z0-9\\-_\\(\\)\\-].*\\s+select[ a-z0-9'\"\\*,_\\(\\)\\-]+from[ a-z0-9\\-_\\(\\)\\-]+(--|;)",
	";\\s*update\\s+[ a-z0-9\\-_\\(\\)\\-]+\\s+set(\\s+[a-z0-9\\-_]+\\s+=\\s*.+\\s*,)*\\s+[a-z0-9\\-_\\-]+\\s*=\\s*.+\\s*(--|;)",
	";\\s*delete\\s+from\\s+[ a-z0-9\\-_\\(\\)\\-]+\\s*.*(--|;)",
	";\\s*drop\\s+(table|view|index)\\s+[ a-z0-9\\-_\\(\\)\\-]+(--|;)",
	";\\s*truncate\\s+table\\s+[ a-z0-9\\-_\\(\\)\\-]+(--|;)",
	";\\s*alter\\s+table\\s+[ a-z0-9\\-_\\(\\)\\-]+(\\s)+(add|drop\\s+column|alter\\s+column|modify|rename\\s+column)(\\s)+.+(--|;)",
	";\\s*create\\s+table\\s+[ a-z0-9\\-_\\(\\)\\-]+\\s*\\((\\s*[a-z0-9\\-_]+\\s+[ a-z0-9_\\(\\)\\-]+\\s*,)*\\s*[a-z0-9\\-_]+\\s+[ a-z0-9_\\(\\)\\-]+\\)\\s*(--|;)",
	";\\s*create\\s+table\\s+[ a-z0-9\\-_\\(\\)]+\\s*as\\s+select[ a-z0-9'\"\\*,_\\(\\)\\-]+from[ a-z0-9\\-_\\(\\)]+.*(--|;)",
	";\\s*create\\s+(recursive|temporary)?\\s*view\\s+[ a-z0-9\\-_\\(\\)]+.*\\s+as\\s+select[ a-z0-9'\"\\*,_\\(\\)\\-]+from[ a-z0-9\\-_\\(\\)]+.*(--|;)",
	";\\s*create(\\s+unique)?\\s+index\\s+[ a-z0-9\\-_\\(\\)]+\\s+on.*(--|;)"}
