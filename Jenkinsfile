pipeline {
    agent { docker { image 'mcr.microsoft.com/dotnet/core/runtime:3.1' } }
    stages {
        stage('build') {
            steps {
                sh 'cd src'
                sh 'dotnet publish -c release -o build'
            }
        }
    }
}