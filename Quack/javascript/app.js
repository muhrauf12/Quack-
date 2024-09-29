

// Initialize the microphone, sound input, and visualizer
let mic;
let canvas;
let isRecording = false;  // Track if the microphone is recording

function setup() {
    canvas = createCanvas(800, 100);
    canvas.parent('sound-wave');
    mic = new p5.AudioIn();
    mic.start();
}

function draw() {
    background(234);
    let vol = mic.getLevel();
    fill(0, 255, 0);
    let h = map(vol, 0, 1, 0, height);
    rect(width / 2, height - h, 50, h);
}

// Speech recognition setup
const microphoneBtn = document.getElementById('microphone-btn');
let recognition;

if ('webkitSpeechRecognition' in window) {
    recognition = new webkitSpeechRecognition();
    recognition.continuous = true;            // Keep listening continuously until stopped
    recognition.interimResults = false;       // Only provide final results
    recognition.lang = 'en-US';

    microphoneBtn.addEventListener('click', () => {
        if (isRecording) {
            recognition.stop();               // Stop recording when clicked again
            isRecording = false;
            microphoneBtn.style.color = 'black'; // Reset microphone button color
        } else {
            recognition.start();              // Start recording on the first click
            isRecording = true;
            microphoneBtn.style.color = 'red';   // Change color to indicate recording
        }
    });

    recognition.onresult = function(event) {
        const transcript = event.results[0][0].transcript;
        console.log("You said: " + transcript);
        
        if (!isRecording) {
            sendToOpenAI(transcript);         // Only send transcript after stopping recording
        }
    };

    recognition.onerror = function(event) {
        console.error("Speech recognition error", event.error);
    };
}

// Function to send the transcript to OpenAI API
async function sendToOpenAI(transcript) {

    const endpoint = 'https://api.openai.com/v1/completions';

    const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            model: "text-davinci-003",  // You can adjust the model as needed
            prompt: `This user is describing a coding bug: "${transcript}". What might be causing this issue and how can they fix it?`,
            max_tokens: 150,
            temperature: 0.7
        })
    });

    const data = await response.json();
    displayAIResponse(data.choices[0].text);
}

// Display the AI response
function displayAIResponse(response) {
    const aiResponseElement = document.getElementById('ai-response');
    aiResponseElement.textContent = response;
}

