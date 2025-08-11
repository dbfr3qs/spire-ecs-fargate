import React, { useState, useEffect } from 'react';
import './App.css';

function App() {
  const [spireData, setSpireData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [apiResult, setApiResult] = useState(null);
  const [apiLoading, setApiLoading] = useState(false);

  // Fetch SPIRE and ECS information
  const fetchSpireInfo = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await fetch('/api/spire-info');
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Failed to fetch SPIRE information');
      }
      
      setSpireData(data);
    } catch (err) {
      console.error('Error fetching SPIRE info:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Call API service through Envoy
  const callAPIService = async () => {
    try {
      setApiLoading(true);
      setApiResult(null);
      
      const response = await fetch('/api-call');
      const data = await response.json();
      
      setApiResult(data);
    } catch (err) {
      console.error('Error calling API service:', err);
      setApiResult({
        success: false,
        error: `Request failed: ${err.message}`,
        endpoint: '/api-call',
        transport: 'Plain HTTP to Envoy → mTLS → API Service'
      });
    } finally {
      setApiLoading(false);
    }
  };

  // Load data on component mount
  useEffect(() => {
    fetchSpireInfo();
  }, []);

  // Format date for display
  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    try {
      return new Date(dateString).toLocaleString();
    } catch {
      return dateString;
    }
  };

  // Render SPIRE identity section
  const renderSpireIdentity = () => {
    if (!spireData?.spire) return null;
    
    const { spire } = spireData;
    const isSuccess = spire.attestation_status === 'SUCCESS';
    
    return (
      <div className={`section ${isSuccess ? 'info' : 'error'}`}>
        <h2>
          <span className={`status-indicator ${isSuccess ? 'status-success' : 'status-error'}`}></span>
          🆔 SPIFFE Identity Information
        </h2>
        <div className="cert-info">
          <div className="field">
            <span className="label">SPIFFE ID:</span>
            <span className="value">{spire.spiffe_id || 'Not available'}</span>
          </div>
          <div className="field">
            <span className="label">Attestation Status:</span>
            <span className="value">{spire.attestation_status}</span>
          </div>
          {spire.x509_svid_parsed && (
            <>
              <div className="field">
                <span className="label">Certificate Subject:</span>
                <span className="value">{spire.x509_svid_parsed.subject}</span>
              </div>
              <div className="field">
                <span className="label">Certificate Issuer:</span>
                <span className="value">{spire.x509_svid_parsed.issuer}</span>
              </div>
              <div className="field">
                <span className="label">Valid Until:</span>
                <span className="value">{formatDate(spire.x509_svid_parsed.not_after)}</span>
              </div>
            </>
          )}
        </div>
      </div>
    );
  };

  // Render ECS metadata section
  const renderECSMetadata = () => {
    if (!spireData?.ecs) return null;
    
    const { ecs } = spireData;
    
    return (
      <div className="section info">
        <h2>🚢 ECS Task Metadata</h2>
        <div className="cert-info">
          <div className="field">
            <span className="label">Cluster:</span>
            <span className="value">{ecs.Cluster || 'N/A'}</span>
          </div>
          <div className="field">
            <span className="label">Task ARN:</span>
            <span className="value">{ecs.TaskARN || 'N/A'}</span>
          </div>
          <div className="field">
            <span className="label">Family:</span>
            <span className="value">{ecs.Family || 'N/A'}</span>
          </div>
          <div className="field">
            <span className="label">Service Name:</span>
            <span className="value">{ecs.ServiceName || 'N/A'}</span>
          </div>
          <div className="field">
            <span className="label">Launch Type:</span>
            <span className="value">{ecs.LaunchType || 'N/A'}</span>
          </div>
          <div className="field">
            <span className="label">Availability Zone:</span>
            <span className="value">{ecs.AvailabilityZone || 'N/A'}</span>
          </div>
        </div>
      </div>
    );
  };

  // Render API call result
  const renderApiResult = () => {
    if (!apiResult) return null;
    
    const resultClass = apiResult.success ? 'success' : 'error';
    const icon = apiResult.success ? '✅' : '❌';
    
    return (
      <div className={`api-result ${resultClass}`}>
        <h3>{icon} API Service Response</h3>
        <p><strong>Transport:</strong> {apiResult.transport}</p>
        <p><strong>Endpoint:</strong> {apiResult.endpoint}</p>
        
        {apiResult.success ? (
          <>
            <p><strong>Service:</strong> {apiResult.response?.service_name} v{apiResult.response?.version}</p>
            <p><strong>Status:</strong> {apiResult.response?.status}</p>
            <p><strong>API Service Identity:</strong> {apiResult.response?.data?.spiffe_id}</p>
            <p><strong>Timestamp:</strong> {formatDate(apiResult.response?.timestamp)}</p>
            <details>
              <summary><strong>Full Response Data</strong></summary>
              <pre>{JSON.stringify(apiResult, null, 2)}</pre>
            </details>
          </>
        ) : (
          <p><strong>Error:</strong> {apiResult.error}</p>
        )}
      </div>
    );
  };

  return (
    <div className="container">
      <div className="header">
        <h1>🌐 SPIRE Envoy Service Mesh Demo</h1>
        <p>ECS Fargate Task Identity with Envoy Proxy mTLS - React Edition</p>
        <div className="architecture-note">
          <strong>🏗️ Service Mesh Architecture:</strong> This React application communicates through Envoy Proxy sidecars. 
          mTLS is handled transparently by Envoy using SPIRE-issued certificates, while applications use plain HTTP.
        </div>
        <button 
          className="refresh-btn" 
          onClick={fetchSpireInfo}
          disabled={loading}
        >
          {loading ? (
            <>
              <span className="spinner"></span>
              🔄 Refreshing...
            </>
          ) : (
            '🔄 Refresh'
          )}
        </button>
      </div>

      <div className="section api-section">
        <h2>🌐 Service Mesh API Communication</h2>
        <p>Test service-to-service communication through Envoy Proxy with automatic mTLS:</p>
        <button 
          className="api-call-btn" 
          onClick={callAPIService}
          disabled={apiLoading}
        >
          {apiLoading ? (
            <>
              <span className="spinner"></span>
              🔄 Calling...
            </>
          ) : (
            '📡 Call API Service via Envoy'
          )}
        </button>
        {renderApiResult()}
      </div>

      {error && (
        <div className="section error">
          <h2>❌ Error</h2>
          <p>{error}</p>
        </div>
      )}

      {loading && !spireData && (
        <div className="section info">
          <h2>
            <span className="spinner"></span>
            Loading SPIRE Information...
          </h2>
          <p>Connecting to SPIRE agent and fetching identity information...</p>
        </div>
      )}

      {spireData && !loading && (
        <>
          {renderSpireIdentity()}
          {renderECSMetadata()}
        </>
      )}

      <div className="section info">
        <h2>🔧 Technical Details</h2>
        <div className="cert-info">
          <div className="field">
            <span className="label">Frontend:</span>
            <span className="value">React 18.2.0</span>
          </div>
          <div className="field">
            <span className="label">Backend:</span>
            <span className="value">Node.js + Express</span>
          </div>
          <div className="field">
            <span className="label">Proxy:</span>
            <span className="value">Envoy Sidecar</span>
          </div>
          <div className="field">
            <span className="label">Security:</span>
            <span className="value">SPIRE mTLS (transparent)</span>
          </div>
          <div className="field">
            <span className="label">Architecture:</span>
            <span className="value">React → Node.js → Envoy → mTLS → API Service</span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
