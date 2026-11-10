fetch("data/kev-dashboard.json")
.then(response => response.json())
.then(data => {

    console.log(data);

    document.getElementById("stats").innerHTML =
    `
    <p>
        KEV Totaux : ${data.total_kev}<br>
        Nouveaux CVE 30 jours : ${data.new_cve_30d}
    </p>
    `;

    const tbody = document.querySelector("#kevTable tbody");

    if (data.latest_kev && data.latest_kev.length > 0) {

        data.latest_kev.forEach(item => {

            tbody.innerHTML += `
            <tr>
                <td>${item.cve}</td>
                <td>${item.vendor}</td>
                <td>${item.date}</td>
                <td>${item.cvss}</td>
            </tr>
            `;

        });

    }

})
.catch(error => {

    console.error("Erreur JSON :", error);

    document.getElementById("stats").innerHTML =
    "<p style='color:red'>Impossible de charger les données.</p>";

});
