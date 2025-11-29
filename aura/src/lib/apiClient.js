const API_BASE_URL = 'http://localhost:8000/api';

/**
 * Helper function to handle API responses
 */
async function handleResponse(response) {
    if (!response.ok) {
        const error = await response.text();
        throw new Error(error || response.statusText);
    }
    return response.json();
}

/**
 * API Client for communicating with the Django backend
 */
export const apiClient = {
    /**
     * Fetch recent threat logs/attacks
     * @returns {Promise<Array>} List of attacks
     */
    getAttacks: async () => {
        try {
            const response = await fetch(`${API_BASE_URL}/attacks/`);
            return await handleResponse(response);
        } catch (error) {
            console.warn("API Error (getAttacks):", error);
            return []; // Return empty array on error to prevent UI crash
        }
    },

    /**
     * Fetch system statistics (total events, threats, breaches, health)
     * @returns {Promise<Object>} Stats object
     */
    getStats: async () => {
        try {
            const response = await fetch(`${API_BASE_URL}/stats/`);
            return await handleResponse(response);
        } catch (error) {
            console.warn("API Error (getStats):", error);
            return {
                total: 0,
                threats: 0,
                breaches: 0,
                health: 100
            };
        }
    },

    /**
     * Fetch attack traffic data for the map/chart
     * @returns {Promise<Array>} Traffic data points
     */
    getAttackTraffic: async () => {
        try {
            const response = await fetch(`${API_BASE_URL}/traffic/`);
            return await handleResponse(response);
        } catch (error) {
            console.warn("API Error (getAttackTraffic):", error);
            return [];
        }
    },
        /**
     * Upload a PCAP file for analysis
     * @param {File} file - The PCAP file to upload
     * @returns {Promise<Object>} Analysis results
     */
    uploadPCAP: async (file) => {
        try {
            const formData = new FormData();
            formData.append('file', file);

            // 👉 point to the real Django endpoint
            const response = await fetch(`${API_BASE_URL}/upload-capture/`, {
                method: 'POST',
                body: formData,
            });

            // This gives us Django JSON: { message, summary, csv, total_requests }
            const data = await handleResponse(response);

            // Shape it so Scan.jsx understands it
            return {
                status: 'ok',               // ✅ Scan.jsx checks this
                message: data.message,
                summary: data.summary || {},
                csv: data.csv || null,
                total_requests: data.total_requests || 0,
            };
        } catch (error) {
            console.warn("API Error (uploadPCAP):", error);
            return {
                status: 'error',
                message: error.message || 'Upload failed',
            };
        }
    }

};
