fetch("data/kev-dashboard.json")
.then(r => r.json())
.then(data => {

document.getElementById("stats").innerHTML =
`
<p>
KEV Totaux : ${data.total_kev}<br>
Nouveaux CVE 30 jours : ${data.new_cve_30d}
</p>
`;

let tbody =
document.querySelector("#kevTable tbody");

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

})
.catch(error => {
    console.error(error);
    document.getElementById("stats").innerHTML =
        "<p style='color:red'>Impossible de charger les données.</p>";
});