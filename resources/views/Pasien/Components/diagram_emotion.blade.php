<!-- Data Diagram -->
<div class="max-w-lg w-full flex flex-col rounded-2xl bg-white bg-clip-border text-gray-700 shadow-lg mb-5 relative h-[300px]">
    <div class="w-full relative">
        <div id="bar-chart" class="relative"></div>
        <!-- Overlay untuk gambar -->
        <div id="xaxis-images" class="absolute top-[240px] -bottom-12 left-1/2 -translate-x-1/2 w-fit flex justify-between ml-2">
        </div>
    </div>
</div>

<!-- Chart JS -->
<script src="https://cdn.jsdelivr.net/npm/apexcharts"></script>

<script>
    // Data dari Laravel
    const emotionData = @json($emotionData); // Data dari controller

    // Pastikan nama kategori sesuai dengan JSON dari `emotionData`
    const categories = [
        { name: "neutral", icon: "{{ asset('icons/Neutral.svg') }}", label: "Netral" },
        { name: "joy", icon: "{{ asset('icons/Joy.svg') }}", label: "Senang" },
        { name: "sadness", icon: "{{ asset('icons/Sadness.svg') }}", label: "Sedih" },
        { name: "surprise", icon: "{{ asset('icons/Surprise.svg') }}", label: "Terkejut" },
        { name: "disgust", icon: "{{ asset('icons/Disgust.svg') }}", label: "Jijik" },
        { name: "anger", icon: "{{ asset('icons/Anger.svg') }}", label: "Marah" },
        { name: "fear", icon: "{{ asset('icons/Fear.svg') }}", label: "Takut" },
    ];

    // Debugging: Periksa `emotionData` dari Laravel
    console.log("Emotion Data:", emotionData);

    // Ekstrak skor berdasarkan label
    const scores = categories.map((category) => {
        const match = emotionData.find((e) => e.label === category.name);
        return match ? parseFloat(match.score).toFixed(2) : 0; // Skor 0 jika tidak ditemukan
    });

    // Debugging: Periksa hasil `scores`
    console.log("Processed Scores:", scores);

    // Konfigurasi Chart
    const chartConfig = {
        series: [
            {
                name: "Emosi",
                data: scores, // Gunakan skor dari data controller
            },
        ],
        chart: {
            type: "bar",
            height: 240,
            toolbar: {
                show: false,
            },
        },
        title: {
            show: false,
        },
        dataLabels: {
            enabled: true, // Aktifkan label data
            formatter: (val) => `${parseFloat(val).toFixed(2)}`, // Format angka ke 2 desimal
            style: {
                fontSize: '12px',
                fontFamily: 'inherit',
                colors: ['#063248'], // Warna teks label
            },
            offsetY: -15, // Geser posisi label ke atas batang
        },
        colors: ["#298EA6"],
        plotOptions: {
            bar: {
                columnWidth: "40%",
                borderRadius: 2,
                dataLabels: {
                    position: "top", // Posisi label di atas batang
                },
            },
        },
        xaxis: {
            categories: categories.map((c) => c.name), // Gunakan nama kategori
            labels: {
                show: false, // Sembunyikan label default
            },
        },
        yaxis: {
            min: 0, // Nilai minimum tetap 0
            max: 1, // Nilai maksimum tetap 1
            labels: {
                formatter: (val) => parseFloat(val).toFixed(2), // Format angka ke 2 desimal
                style: {
                    colors: "#616161",
                    fontSize: "12px",
                    fontFamily: "inherit",
                    fontWeight: 400,
                },
            },
        },
        grid: {
            show: true,
            borderColor: "#dddddd",
            strokeDashArray: 5,
            xaxis: {
                lines: {
                    show: true,
                },
            },
            padding: {
                top: 5,
                right: 20,
            },
        },
        fill: {
            opacity: 0.8,
        },
        tooltip: {
            theme: "dark",
            y: {
                formatter: (val) => `${parseFloat(val).toFixed(2)}`, // Format angka ke 2 desimal
            },
        },
    };

    // Render Chart
    const chart = new ApexCharts(document.querySelector("#bar-chart"), chartConfig);
    chart.render().then(() => {
        // Tambahkan gambar dan label di bawah x-axis setelah grafik dirender
        const xaxisImagesContainer = document.getElementById("xaxis-images");

        categories.forEach((category) => {
            const imgContainer = document.createElement("div");
            imgContainer.classList.add(
                "flex", "flex-col", "items-center", "w-[58px]", "text-center"
            );

            // Tambahkan gambar dan label dalam bahasa Indonesia
            imgContainer.innerHTML = `
                <img src="${category.icon}" alt="${category.name}" class="w-10 h-5 mb-2">
                <span class="text-[0.75rem] text-gray-700">${category.label}</span>
            `;

            xaxisImagesContainer.appendChild(imgContainer);
        });
    });
</script>
