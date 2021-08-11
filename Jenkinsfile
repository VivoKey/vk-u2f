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
				sh 'mvn -Dmaven.test.failure.ignore=true clean package'
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