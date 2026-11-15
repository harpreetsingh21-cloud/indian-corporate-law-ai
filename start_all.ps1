$backend = "C:\Users\Gurmeet Kaur\Desktop\legalbuddy updated\indian-corporate-law-ai\backend"
$domain  = "stardom-expenses-clumsily.ngrok-free.dev"

Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$backend'; python run_all.py"
Start-Sleep -Seconds 15
Start-Process powershell -ArgumentList "-NoExit", "-Command", "ngrok http --url=$domain 5000"
