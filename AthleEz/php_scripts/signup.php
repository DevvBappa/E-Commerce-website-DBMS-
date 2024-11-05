<?php
// Database connection parameters
$servername = "localhost";
$username = "root";         // Your MySQL username
$password = "";             // Your MySQL password
$dbname = "FabricFinds";    // Your database name

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check the connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Check if the form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Get form data
    $name = $_POST['name'];
    $email = $_POST['email'];
    $password = $_POST['password']; // Password hashing recommended in production
    $role = $_POST['role'];
    $address = isset($_POST['address']) ? $_POST['address'] : null;

    // Simple validation for required fields
    if (!empty($name) && !empty($email) && !empty($password) && !empty($role)) {
        
        // Hash the password for security
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        // Prepare the SQL statement based on the role
        if ($role === 'Customer') {
            $stmt = $conn->prepare("INSERT INTO Customers (name, email, password, address) VALUES (?, ?, ?, ?)");
            $stmt->bind_param("ssss", $name, $email, $hashed_password, $address);
        } elseif ($role === 'Seller') {
            $stmt = $conn->prepare("INSERT INTO Sellers (name, email, password, address) VALUES (?, ?, ?, ?)");
            $stmt->bind_param("ssss", $name, $email, $hashed_password, $address);
        } elseif ($role === 'Admin') {
            $stmt = $conn->prepare("INSERT INTO Admins (name, email, password) VALUES (?, ?, ?)");
            $stmt->bind_param("sss", $name, $email, $hashed_password);
        } else {
            echo "Invalid role selected.";
            exit;
        }

        // Execute the prepared statement
        if ($stmt && $stmt->execute()) {
            header("Location: /Project1/html_scripts/signin.html"); // Redirect to signin page
            exit;
        } else {
            echo "Error: " . $stmt->error;
        }

        // Close the statement
        $stmt->close();
    } else {
        echo "Please fill in all required fields.";
    }
}

// Close the connection
$conn->close();
?>
