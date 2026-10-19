"""Utility functions for quantum experiments."""

from qiskit import QuantumCircuit
from qiskit.providers import Backend
from qiskit.transpiler.preset_passmanagers import generate_preset_pass_manager
from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2 as Sampler


from traitlets import Callable, Any
from functools import wraps
import keyring
import numpy as np


# retrieve the API key from the keyring
service_name = "https://quantum.cloud.ibm.com/"
username = "JulesVerneKey"
backend_name = "ibm_fez"  # all ibm backends start by ibm_ and follow by a city name, for example ibm_lagos, ibm_perth, ibm_cairo, ibm_mumbai, etc.
ibm_quantum_channel = "ibm_quantum_platform"
api_key = None


# retrieving the API KEY
def get_api_key(service_name: str=service_name, username: str=username) -> str:
    """Retrieve the API key from the keyring.
    
    :param service_name: The name of the service for which to retrieve the API key. Set by default to the IBM Quantum service URL.
    :param username: The username associated with the API key. Set by default to "JulesVerneKey".
    :return: The API key as a string, or None if not found.
    """
    api_key = keyring.get_password(service_name, username)
    if api_key is None:
        print("failed to retrive the API Key")
    else:
        print("API Key retrieved successfully")
    return api_key


def is_service_exist(channel: str=ibm_quantum_channel) -> bool:
    """Check if the QiskitRuntimeService exists and is accessible.
    
    :param channel: The channel for which to check service existence. Set by default to the IBM Quantum platform channel.
    :return: True if the service exists and is accessible, False otherwise.
    """
    try:
        QiskitRuntimeService(channel=channel) # QiskitRuntimeService()
        print("QiskitRuntimeService exists and is accessible.")
        return True
    except Exception as e:
        print(f"QiskitRuntimeService does not exist or is not accessible: {e}")
        return False


def check_service_existence(channel: str=ibm_quantum_channel, set_as_default: bool=False, overwrite: bool=True)-> Any:
    """Decorator to check if the QiskitRuntimeService exists and is accessible before executing a function.
    
    :param channel: The channel for which to check service existence. Set by default to the IBM Quantum platform channel.
    :param set_as_default: Whether to set the service as default if it does not exist. Set by default to False.
    :param overwrite: Whether to overwrite the existing service if it does not exist. Set by default to True.
    :return: The result of the decorated function if the service exists, or None otherwise."""
    def catch_function(func: Callable) -> Callable:
        @wraps(func) # to preserve the original function's metadata as example_function.__name__ or example_function.__doc__ it will return the original function's name and docstring instead of the wrapper's name and docstring.
        def wrapper(*args, **kwargs):
            if not is_service_exist(channel):
                print("QiskitRuntimeService does not exist or is not accessible.")
                QiskitRuntimeService.save_account(channel=channel, token=get_api_key(), overwrite=overwrite, set_as_default=set_as_default)
            return func(*args, **kwargs)
        return wrapper
    return catch_function


@check_service_existence(channel=ibm_quantum_channel)
def get_backend(backend_name: str=backend_name) -> Backend:
    """Retrieve the backend from the QiskitRuntimeService.
    
    ..NOTE:  service is by default set. see library utils.py for more details.
    
    :param backend_name: The name of the backend to retrieve. Set by default to "ibm_fez".
    :return: The backend object.
    """
    service = QiskitRuntimeService(channel=ibm_quantum_channel) # QiskitRuntimeService()
    # print all existing backends
    print(f"Available backends: {service.backends()}")
    # select the least busy backend
    backend = service.least_busy(operational=True, simulator=False, min_num_qubits=127)
    if not backend.status().operational:
        # we take the first operational backend available from the list of available backends
        backend = [b for b in service.backends() if b.status().operational and not b.configuration().simulator and b.name != backend.name][0]
    # or specify the backend by name directly
    #backend = service.backend(backend_name)
    print(f"selecting backend name: {backend.name} with {backend.num_qubits} qubits")

    if not backend: # if the no backend found, we can try to get it by name
        service = QiskitRuntimeService(channel=ibm_quantum_channel)
        backend = service.backend(backend_name)
    return backend

# We will define a function to run the circuit on a simulator or real machine and retrieve the results.
def run_circuit_and_get_counts(circuit:QuantumCircuit, backend:Backend, shots:int=1024, optimization_level:int=1)->dict:
    """Run the circuit on a simulator or real machine and retrieve the results.
    
    :param circuit: The quantum circuit to run.
    :param backend: the backend to run the circuit on (Qiskit backend of real device or simulator).
    :param shots: The number of shots to run the circuit for.
    :param optimization_level: The level of optimization to apply to the circuit.
    :return: A dictionary counts of the measurement results.
    """
    # get the backend from the name
    preset_pass_manager = generate_preset_pass_manager(backend=backend, optimization_level=optimization_level)
    circuit_running = preset_pass_manager.run(circuit)
    # creation of the Sampler
    sampler = Sampler(mode=backend)
    # run the circuit on the backend as many times as specified by the shots parameter
    job = sampler.run([circuit_running], shots=shots)
    results = job.result()
    return results[0].data.meas.get_counts()


def _sqrt_psd(A):
    """Matrix square root of a Hermitian positive semidefinite matrix."""
    w, v = np.linalg.eigh(A)
    w = np.clip(w, 0, None)  # remove tiny negative numerical noise
    return (v * np.sqrt(w)) @ v.conj().T
 
 
def fidelity(rho, sigma, tol=1e-8):
    """
    Uhlmann fidelity F = (Tr sqrt( sqrt(rho) sigma sqrt(rho) ))^2
    between two density matrices (works for any rho, sigma,
    including the case where one of them is diagonal).
    Returns a value between 0 and 1.
    """
    rho = np.asarray(rho, dtype=complex)
    sigma = np.asarray(sigma, dtype=complex)
 
    # basic checks
    if rho.shape != sigma.shape or rho.ndim != 2 or rho.shape[0] != rho.shape[1]:
        raise ValueError("Both inputs must be square matrices of the same size.")
    for name, m in (("rho", rho), ("sigma", sigma)):
        if not np.allclose(m, m.conj().T, atol=tol):
            raise ValueError(f"{name} is not Hermitian.")
        if abs(np.trace(m) - 1) > tol:
            raise ValueError(f"{name} does not have trace 1.")
        if np.linalg.eigvalsh(m).min() < -tol:
            raise ValueError(f"{name} is not positive semidefinite.")
 
    sr = _sqrt_psd(rho)
    M = sr @ sigma @ sr # matrix multiplication
    M = (M + M.conj().T) / 2  # enforce Hermiticity numerically
    eigs = np.clip(np.linalg.eigvalsh(M), 0, None)
    F = np.sum(np.sqrt(eigs)) ** 2
    return float(min(F, 1.0))


if __name__ == "__main__":
    # rho diagonal, sigma general
    #rho = np.diag([0.8, 0.2,])
    rho = np.array([[1, 0],
                    [0, 0],])
    sigma = np.array([[0.5, 0.5],
                      [0.5, 0.5],])
    print("F(rho, sigma) =", fidelity(rho, sigma))
    print("F(sigma, rho) =", fidelity(sigma, rho))  # should be identical
    print("F(rho, rho)   =", fidelity(rho, rho))    # should be 1