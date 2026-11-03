# Proxy and Content Filtering System

## Project Overview

The **Proxy and Content Filtering System** is a network security project that implements a concurrent TCP proxy to control and filter client requests to backend services.

The system monitors incoming requests, applies configurable filtering policies, and dynamically allows or blocks traffic. It integrates an SDN controller using OS-Ken and a Mininet network environment to enforce network-level filtering rules.

The project aims to improve network security, provide centralized traffic control, and evaluate the performance overhead introduced by proxy-based filtering.

## Objectives

- Develop a concurrent TCP proxy server.
- Intercept and analyze client requests.
- Implement configurable content filtering policies.
- Allow or block traffic based on predefined rules.
- Integrate the proxy with an SDN controller.
- Dynamically install and remove network filtering rules.
- Log permitted and blocked requests.
- Measure proxy overhead and performance.

## Project Architecture

The system consists of the following major components:

1. **Client:** Generates HTTP requests to access backend services.
2. **TCP Proxy:** Intercepts client requests and forwards valid requests.
3. **Content Filtering Engine:** Checks requests against configurable policies.
4. **SDN Controller (OS-Ken):** Manages dynamic network filtering rules.
5. **Mininet Network:** Simulates the network using Open vSwitch.
6. **Backend Server:** Processes permitted requests and returns responses.
7. **Dashboard and Monitoring:** Displays logs, statistics, and monitoring information.
8. **Policy Configuration:** Stores filtering rules and parameters in `policy.json`.

### Request Flow

1. The client sends a request to the TCP proxy.
2. The proxy receives and analyzes the request.
3. The content filtering engine checks the request against configured policies.
4. Permitted requests are forwarded to the backend server.
5. Blocked requests are denied.
6. Policy violations can trigger dynamic SDN filtering rules.
7. The response is returned to the client.
8. Request information and performance metrics are recorded.

## Technologies Used

- Python
- TCP Socket Programming
- Mininet
- Open vSwitch (OVS)
- OS-Ken SDN Controller
- HTTP Protocol
- JSON
- Linux

## Key Features

- Concurrent TCP proxy handling
- Configurable content filtering
- Keyword-based request filtering
- Host-based filtering policies
- Dynamic SDN-based traffic blocking
- Client block and unblock functionality
- Request logging
- Performance evaluation
- Dashboard-based monitoring

## Project Structure

```text
project28/
│
├── proxy.py
├── client.py
├── service.py
├── controller.py
├── topology.py
├── rules.py
├── policy.json
│
├── lab.py
├── harness.py
├── dashboard.py
├── ui/
│   └── index.html
│
├── test_proxy_http.py
├── test_rules.py
├── run_tests.py
├── bench.py
├── traffic.py
├── run_experiments.py
│
├── results/
│
├── README.md
└── POLISH_NOTES.md
```

## Team Contribution and File Distribution

The project was divided among three team members based on functionality.

### Prajwal M R – TCP Proxy and Client Implementation

**Files handled:**
- `proxy.py`
- `client.py`
- `service.py`

**Responsibilities:**
- Implemented TCP proxy functionality.
- Developed client request handling.
- Implemented backend service communication.
- Implemented request forwarding and response handling.
- Worked on application-layer content filtering.
- Tested permitted and blocked requests.

### Moola Adithya– SDN Controller and Network Topology

**Files handled:**
- `controller.py`
- `topology.py`
- `rules.py`
- `policy.json`
- `lab.py`

**Responsibilities:**
- Implemented the OS-Ken SDN controller.
- Configured the Mininet network topology.
- Implemented dynamic SDN filtering rules.
- Configured filtering policies.
- Integrated network-level traffic control.
- Tested SDN rule installation and client blocking.

### Nishanth U– Testing, Performance Evaluation, and Dashboard

**Files handled:**
- `test_proxy_http.py`
- `test_rules.py`
- `run_tests.py`
- `bench.py`
- `traffic.py`
- `run_experiments.py`
- `harness.py`
- `dashboard.py`
- `ui/index.html`
- `README.md`
- `POLISH_NOTES.md`

**Responsibilities:**
- Developed and executed test cases.
- Verified proxy and filtering functionality.
- Evaluated system performance and proxy overhead.
- Worked on dashboard and monitoring functionality.
- Prepared project documentation.
- Assisted with integration testing and final demonstration.

### Integration

All three members contributed to the integration and verification of the complete system. The project components were combined to demonstrate TCP proxying, content filtering, SDN-based traffic control, and performance evaluation.

## Configuration

Filtering policies are maintained in `policy.json`.

The configuration supports:

- Banned keywords
- Blocked hosts
- Denied clients
- Allowed HTTP methods
- Client blocking parameters
- Strike limits and time windows

The policy configuration can be modified to customize filtering behavior.

## Testing and Performance Evaluation

The project includes testing and performance evaluation scripts to verify functionality and measure system performance.

Testing includes:

- Permitted HTTP requests
- Blocked requests
- Content filtering verification
- Dynamic SDN rule installation
- Client blocking and unblocking
- Proxy performance measurement
- Request overhead evaluation

## Expected Outcome

The system provides a functional TCP proxy with configurable content filtering and dynamic SDN-based traffic control. It demonstrates the integration of application-layer filtering with software-defined networking in a simulated environment.

## Conclusion

The Proxy and Content Filtering System demonstrates how TCP proxying, configurable security policies, and SDN integration can be combined to create a network traffic filtering solution.

The project provides practical experience in socket programming, network emulation, traffic control, security policy enforcement, and performance evaluation.

## Project Information

**Project Type:** Computer Networks – Final Project

**Protocol:** TCP

**Network Environment:** Mininet

**SDN Controller:** OS-Ken
