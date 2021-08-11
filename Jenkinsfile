pipeline {
    agent any
    tools {
        maven 'DefaultMaven'
        jdk 'JDK8'
		ant 'Default'
    }
    stages {
		stage ('Submodule Update') {
			steps {
				sh 'git submodule update --init'
			}
		}
        stage ('Build') {
            steps {
				sh 'maven clean'
				sh 'maven package'
            }
            post {
                always {
					archiveArtifacts artifacts: 'target/*.cap', fingerprint: true
                    junit 'target/surefire-reports/*.xml'
                }
            }
        }
    }
}