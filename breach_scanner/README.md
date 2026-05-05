## 1. What this service does
This service scans an email against a local dataset to identify breaches.

## 2. File explanations
- main.py: Contains the FastAPI application and the API endpoint for scanning emails.
- service.py: Implements the logic for scanning emails, including loading the dataset, filtering matches, computing severity, and formatting the response.
- models.py: Defines the Pydantic model for the email request.
- data.json: A local JSON file containing the breach dataset with email, breach name, year, and data exposed.

## 3. API details
- Endpoint: POST /scan/email
- Port: Default 8001
- Input format: {"email": "user@gmail.com"}
- Output format: {"breaches": [{"name": "LinkedIn", "year": 2021, "data_exposed": ["email", "password"], "severity": "HIGH", "source": "LOCAL"}]}

## 4. How to run locally
1. Install dependencies: pip install fastapi uvicorn pydantic
2. Run the service: uvicorn main:app --host 0.0.0.0 --port 8001
3. Open Swagger UI: Navigate to http://localhost:8001/docs
4. Test the endpoint: Use the POST /scan/email endpoint with a JSON body containing an email.

## 5. Information for integration
- Service URL: http://breach-scanner:8001
-Local:
http://localhost:8001/scan/email
-Docker:
http://breach-scanner:8001/scan/email
- Port number: 8001
- Endpoint path: /scan/email
- Expected request JSON: {"email": "user@gmail.com"}
- Expected response JSON: {"breaches": [{"name": "LinkedIn", "year": 2021, "data_exposed": ["email", "password"], "severity": "HIGH", "source": "LOCAL"}]}

## 6. How this will connect to other services
This service will be called by an API Gateway via HTTP requests. It does not use a database and communicates through RESTful APIs.

## 7. What will change later
- The local dataset will be replaced with external APIs.
- A Dockerfile will be added for containerization.
- The service will run inside a container.
- It will integrate with an API Gateway.
- Deployment will occur on AWS.