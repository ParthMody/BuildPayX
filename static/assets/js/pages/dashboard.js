//----------------------------------
//          SUBCONTRACTOR
//----------------------------------
var sc = {
	annotations: {
		position: 'back'
	},
	dataLabels: {
		enabled:false
	},
	chart: {
		type: 'bar',
		height: 300
	},
	fill: {
		opacity:1
	},
	plotOptions: {
	},
	series: [{
		name: 'Deliveries',
		data: [5,7,6,8,4,3,6,1]
	}],
	colors: '#435ebe',
	xaxis: {
		categories: ["W1","W2","W3","W4","W5","W6","W7", "W8"],
	},
}


var sc_dash = new ApexCharts(document.getElementById('sc'), sc)
sc_dash.render();


let sc_pie = {
  series: [65, 25, 10],              // out of 100 claims
  labels: [
    'Completed',                     // 65%
    'Pending',                       // 25%
    'On Hold'                        // 10%
  ],
  colors: ['#3245D1', '#FFC107', '#FF4E42'],  // blue, amber, red
  chart: {
    type: 'donut',
    width: '100%',
    height: 350
  },
  legend: {
    position: 'bottom'
  },
  plotOptions: {
    pie: {
      donut: {
        size: '30%'
      }
    }
  }
};


var sc_pie_disp = new ApexCharts(document.getElementById('sc_pie'), sc_pie)
sc_pie_disp.render();


var sc_score = {
  series: [72],
  chart: {
    height: 300,
    type: "radialBar",
    toolbar: {
      show: true,
    },
  },
  plotOptions: {
    radialBar: {
      startAngle: -135,
      endAngle: 225,
      hollow: {
        margin: 0,
        size: "70%",
        background: "#fff",
        image: undefined,
        imageOffsetX: 0,
        imageOffsetY: 0,
        position: "front",
        dropShadow: {
          enabled: true,
          top: 3,
          left: 0,
          blur: 4,
          opacity: 0.24,
        },
      },
      track: {
        background: "#fff",
        strokeWidth: "67%",
        margin: 0, // margin is in pixels
        dropShadow: {
          enabled: true,
          top: -3,
          left: 0,
          blur: 4,
          opacity: 0.35,
        },
      },

      dataLabels: {
        show: true,
        name: {
          offsetY: -10,
          show: true,
          color: "#888",
          fontSize: "17px",
        },
        value: {
          formatter: function(val) {
            return parseInt(val);
          },
          color: "#111",
          fontSize: "36px",
          show: true,
        },
      },
    },
  },
  fill: {
    type: "gradient",
    gradient: {
      shade: "dark",
      type: "horizontal",
      shadeIntensity: 0.5,
      gradientToColors: ["#ABE5A1"],
      inverseColors: true,
      opacityFrom: 1,
      opacityTo: 1,
      stops: [0, 100],
    },
  },
  stroke: {
    lineCap: "round",
  },
  labels: ["Percent"],
};

var sc_score_disp = new ApexCharts(document.querySelector("#sc_score"), sc_score);
sc_score_disp.render()


var sc_line = {
  chart: {
    type: "line",
    height: 300,
    toolbar: { show: false },
    foreColor: "#333"
  },
  series: [
    {
      name: "Avg Approval Time (hrs)",
      data: [2.4, 2.9, 2.7, 3.1, 2.8, 3.0, 2.6, 2.5, 2.9, 3.2, 2.7, 2.8]
    }
  ],
  colors: ["#FD7E14"],            // vibrant orange
  stroke: {
    curve: "smooth",
    width: 3
  },
  markers: {
    size: 5,
    colors: ["#fff"],
    strokeColors: "#FD7E14",
    strokeWidth: 2
  },
  fill: {
    type: "solid",
    gradient: {
      shade: "light",
      type: "vertical",
      gradientToColors: ["#FFC97F"],  // soft peach
      stops: [0, 100],
      opacityFrom: 0.6,
      opacityTo: 0.1
    }
  },
  xaxis: {
    categories: ["Jan", "Feb", "Mar", "Apr", "May", "Jun", 
                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
    title: { text: "Month" },
    axisBorder: { color: "#ddd" },
    axisTicks: { color: "#ddd" }
  },
  yaxis: {
    title: { text: "Hours to Approve" },
    min: 2,
    max: 4,
    axisBorder: { color: "#ddd" },
    axisTicks: { color: "#ddd" }
  },
  grid: {
    borderColor: "#f1f1f1",
    xaxis: { lines: { show: false } }
  },
  tooltip: {
    theme: "light",
    y: {
      formatter: val => `${val.toFixed(1)} hrs`
    }
  }
};

var sc_line_disp = new ApexCharts(document.querySelector("#sc_line"), sc_line);
sc_line_disp.render();

//----------------------------------
//          MATERIAL SUPPLIER
//----------------------------------

// Sample data – swap these for your real AJAX-fetched arrays
const advanceData   = [12000,15000,18000,14000,10000,16000,20000,17000,13000,19000,21000,18000];
const retentionData = [ 2000, 3000,  2500, 2200, 1800, 2400, 2700, 2300, 2000, 2600, 2800, 2400];

var optionsProfileVisit = {
  chart: {
    type: 'bar',
    height: 300, 
	stacked: true     // ← enable stacking
  },
  plotOptions: {
    bar: {
      columnWidth: '50%',
      endingShape: 'flat'
    }
  },
  dataLabels: {
    enabled: false
  },
  series: [
    {
      name: 'Advance (85%)',
      data: advanceData,
      color: '#3245D1'   // chartColors.blue
    },
    {
      name: 'Retention (15%)',
      data: retentionData,
      color: '#41B1F9'   // chartColors.info
    }
  ],
  xaxis: {
    categories: ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"],
    labels: { rotate: -45 }
  },
  yaxis: {
    title: { text: 'Amount (A$)' }
  },
  tooltip: {
    y: {
      formatter: val => `A$ ${val.toLocaleString()}`
    }
  },
  legend: {
    position: 'top'
  },
  fill: {
    opacity: 1
  }
};

let optionsVisitorsProfile = {
  series: [70, 15, 5, 10],
  labels: ['Pass First time', 'Insurance paid', 'Recalled', 'On-Hold'],
  colors: ['#3245D1', '#41B1F9', '#7AAFFD', '#C2D9FF'],  // fixed here
  chart: {
    type: 'donut',
    width: '100%',
    height: 350            // number, not '350px'
  },
  legend: {
    position: 'bottom'
  },
  plotOptions: {
    pie: {
      donut: {
        size: '30%'
      }
    }
  }
};


var lineOptions = {
  chart: {
    type: "line",
    height: 300,
    toolbar: { show: false }
  },
  series: [
    {
      name: "EarlyPay APR (%)",
      data: [8.5, 9.0, 8.8, 9.2, 8.7, 9.1, 8.9, 9.3, 8.6, 9.4, 8.8, 9.0]
    }
  ],
  xaxis: {
    categories: ["Jan", "Feb", "Mar", "Apr", "May", "Jun", 
                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
    title: { text: "Month" }
  },
  yaxis: {
    title: { text: "APR (%)" },
    min: 8,
    max: 10
  },
  stroke: {
    curve: "smooth",
    width: 2
  },
  markers: {
    size: 4
  },
  grid: {
    borderColor: "#e0e0e0"
  },
  tooltip: {
    y: {
      formatter: val => `${val.toFixed(1)}%`
    }
  }
};

var radialGradientOptions = {
  series: [63],
  chart: {
    height: 300,
    type: "radialBar",
    toolbar: {
      show: true,
    },
  },
  plotOptions: {
    radialBar: {
      startAngle: -135,
      endAngle: 225,
      hollow: {
        margin: 0,
        size: "70%",
        background: "#fff",
        image: undefined,
        imageOffsetX: 0,
        imageOffsetY: 0,
        position: "front",
        dropShadow: {
          enabled: true,
          top: 3,
          left: 0,
          blur: 4,
          opacity: 0.24,
        },
      },
      track: {
        background: "#fff",
        strokeWidth: "67%",
        margin: 0, // margin is in pixels
        dropShadow: {
          enabled: true,
          top: -3,
          left: 0,
          blur: 4,
          opacity: 0.35,
        },
      },

      dataLabels: {
        show: true,
        name: {
          offsetY: -10,
          show: true,
          color: "#888",
          fontSize: "17px",
        },
        value: {
          formatter: function(val) {
            return parseInt(val);
          },
          color: "#111",
          fontSize: "36px",
          show: true,
        },
      },
    },
  },
  fill: {
    type: "gradient",
    gradient: {
      shade: "dark",
      type: "horizontal",
      shadeIntensity: 0.5,
      gradientToColors: ["#ABE5A1"],
      inverseColors: true,
      opacityFrom: 1,
      opacityTo: 1,
      stops: [0, 100],
    },
  },
  stroke: {
    lineCap: "round",
  },
  labels: ["Percent"],
};

var chartProfileVisit = new ApexCharts(
  document.querySelector("#chart-profile-visit"),
  optionsProfileVisit
);

var chartVisitorsProfile = new ApexCharts(document.getElementById('chart-visitors-profile'), optionsVisitorsProfile)

var line = new ApexCharts(document.querySelector("#line"), lineOptions);
var radialGradient = new ApexCharts(document.querySelector("#radialGradient"), radialGradientOptions);




chartProfileVisit.render();
chartVisitorsProfile.render();
line.render();
radialGradient.render();