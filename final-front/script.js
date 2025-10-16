document.getElementById("analyzeBtn").addEventListener("click", async () => {
    const flowText = document.getElementById("flowInput").value.trim();
    if (!flowText) {
        alert("Please enter a system flow description.");
        return;
    }

    try {
        const res = await fetch("http://127.0.0.1:8000/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ flow: flowText })
        });

        if (!res.ok) {
            throw new Error("Backend returned an error");
        }

        const data = await res.json();
        populateTable(data.threats);
    } catch (err) {
        console.error(err);
        alert("Error fetching threats. Make sure backend is running.");
    }
});

function populateTable(threats) {
    const tbody = document.querySelector("#resultsTable tbody");
    tbody.innerHTML = ""; // clear old results

    threats.forEach(t => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td>${t.component}</td>
            <td>${t.type}</td>
            <td>${t.description}</td>
        `;
        tbody.appendChild(row);
    });
}
